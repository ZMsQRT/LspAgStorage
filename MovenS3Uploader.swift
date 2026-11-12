import Foundation
import CryptoKit

// MARK: - 凭证

/// S3 / 对象存储的访问凭证；临时凭证可额外携带 Session Token。
///
/// 调用方传入桶、服务地址和访问密钥；临时凭证可携带会话令牌。
public struct MovenS3Credentials: Equatable, Sendable {
    /// 对象所属的桶名，以及发起 PUT 请求的存储服务地址。
    public var bucket: String
    public var endpoint: String
    /// 用于 SigV4 签名的访问密钥；不要将这两个字段写入日志或返回给页面。
    public var accessKeyID: String
    public var secretAccessKey: String
    /// STS 等临时凭证可能附带的会话令牌；为空时按不带令牌的凭证签名。
    public var sessionToken: String = ""
    /// 公开访问对象的 URL 前缀，可指向与上传 endpoint 不同的 CDN。
    /// 配置时，它应已包含对象 key 之前所需的路径，拼接时不会再自动添加 bucket。
    public var publicBaseURL: String = ""
    /// 签名所用区域；为空时尝试从 endpoint 推断，无法推断时使用默认值。
    public var region: String = ""

    public init(bucket: String, endpoint: String, accessKeyID: String, secretAccessKey: String, region: String = "",
         sessionToken: String = "", publicBaseURL: String = "") {
        self.bucket = bucket
        self.endpoint = endpoint
        self.accessKeyID = accessKeyID
        self.secretAccessKey = secretAccessKey
        self.region = region
        self.sessionToken = sessionToken
        self.publicBaseURL = publicBaseURL
    }

    /// 只检查核心字段是否非空；HTTPS、主机和 URL 结构会在构造请求地址时检查。
    public var isConfigured: Bool {
        !bucket.isEmpty && !endpoint.isEmpty && !accessKeyID.isEmpty && !secretAccessKey.isEmpty
    }

    /// 获取签名区域：显式配置优先，其次从 S3 域名推断，最后回退到 `us-east-1`。
    ///
    /// 支持 `s3.<region>`、`s3-<region>` 和 `s3.dualstack.<region>` 等形式，
    /// 也兼容 Backblaze 的数字区域。只在 S3 标签附近查找，避免把桶名误认成区域。
    /// 加速域名或自定义域名可能不含区域，此时服务端应提供正确的 `region`；
    /// 默认区域只是兜底，不能保证与桶的实际区域一致。
    public var resolvedRegion: String {
        if !region.isEmpty { return region }
        let host = (URL(string: endpoint)?.host ?? endpoint).lowercased()
        let parts = host.split(separator: ".").map(String.init)
        func isRegion(_ value: String) -> Bool {
            value.range(of: #"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$"#, options: .regularExpression) != nil
        }
        for (index, label) in parts.enumerated() where label == "s3" || label.hasPrefix("s3-") {
            if label.hasPrefix("s3-") {
                let candidate = String(label.dropFirst(3))
                if isRegion(candidate) { return candidate }
            }
            var next = index + 1
            if next < parts.count && parts[next] == "dualstack" { next += 1 }
            if next < parts.count && isRegion(parts[next]) { return parts[next] }
        }
        return "us-east-1"
    }
}

// MARK: - 错误

public enum MovenS3Error: LocalizedError, Equatable {
    /// 必需的桶名、endpoint 或密钥缺失。
    case notConfigured
    /// 上传或公网地址无法按当前要求构造，例如不是 HTTPS 或包含用户凭据。
    case invalidEndpoint(String)
    /// 存储服务返回非 2xx；附带截断后的响应文本供排查。
    case badStatus(Int, String)
    /// URLSession 返回了无法识别为 HTTP 的响应；HTTP 成功响应的 body 为空仍然有效。
    case emptyResponse

    public var errorDescription: String? {
        switch self {
        case .notConfigured: "S3 credentials are incomplete."
        case .invalidEndpoint(let value): "Invalid S3 endpoint: \(value)"
        case .badStatus(let code, let body): "S3 upload failed (\(code)): \(body)"
        case .emptyResponse: "S3 returned an empty response."
        }
    }
}

// MARK: - 签名

/// AWS Signature V4 的最小实现，只覆盖单次 PUT。
///
/// 之所以自己算签名而不是引入 AWS SDK：这里只有一个「PUT 一个对象」的诉求，
/// 签名算法固定且可测，省掉一个几 MB 的依赖。
enum MovenS3Signer {
    /// `20261020T091500Z` 形式的 amz-date。
    /// 固定使用 POSIX 语言环境和 UTC，避免设备语言、时区影响签名。
    static func amzDate(_ date: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return formatter.string(from: date)
    }

    /// `20261020` 形式的日期戳（用于 scope）。必须与同次签名中的 amz-date 来自同一个日期。
    static func dateStamp(_ date: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd"
        return formatter.string(from: date)
    }

    /// 返回数据的 SHA-256 小写十六进制摘要，用于请求体和规范请求的哈希。
    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// 以 UTF-8 编码消息并计算 HMAC-SHA256；返回原始字节，供后续密钥派生继续使用。
    static func hmacSHA256(key: Data, message: String) -> Data {
        let signature = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: key))
        return Data(signature)
    }

    /// 按 SigV4 规则逐个编码 UTF-8 字节：保留字母、数字及 `-._~`，其余转为大写 `%XX`。
    /// 例如空格是 `%20`，字面量加号是 `%2B`，不能按表单编码把二者混为一谈。
    static func uriEncode(_ value: String) -> String {
        value.utf8.map { byte in
            if (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte)
                || [45, 46, 95, 126].contains(byte) { return String(UnicodeScalar(byte)) }
            return String(format: "%%%02X", byte)
        }.joined()
    }

    /// 从 URL 的已编码路径生成签名路径，不对整个路径做标准化。
    /// 空路径使用 `/`；按 `/` 分段后再解码、编码，能保留重复分隔符和末尾斜杠。
    /// 例如 key 中的空格和 `+` 分别参与签名为 `%20` 和 `%2B`；段内的 `%2F`
    /// 仍表示段内字符，不会被误当作新路径分隔符。
    static func canonicalURI(_ url: URL) -> String {
        let path = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedPath ?? ""
        guard !path.isEmpty else { return "/" }
        // 分段解码再编码，保留路径分隔符，也不会把键内已编码的斜杠当作分隔符。
        return path.split(separator: "/", omittingEmptySubsequences: false)
            .map { uriEncode(String($0).removingPercentEncoding ?? String($0)) }.joined(separator: "/")
    }

    /// 按 SigV4 构造规范查询串：保留重复参数，分别编码名称和值，再先按名称、
    /// 后按值排序。没有 `=` 的参数按空值处理，签名中仍写成 `name=`。
    /// 这里使用百分号解码而非表单解码，因此原始 `+` 保持为字面量加号。
    /// 例如 `z=2&a=1&a=0` 的签名查询串为 `a=0&a=1&z=2`；无查询参数时为空串。
    static func canonicalQuery(_ url: URL) -> String {
        guard let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedQuery,
              !query.isEmpty else { return "" }
        let items: [(String, String)] = query.split(separator: "&", omittingEmptySubsequences: false).map { item in
            let parts = item.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let key = String(parts[0]).removingPercentEncoding ?? String(parts[0])
            let rawValue = parts.count == 2 ? String(parts[1]) : ""
            return (uriEncode(key), uriEncode(rawValue.removingPercentEncoding ?? rawValue))
        }
        return items.sorted { $0.0 == $1.0 ? $0.1 < $1.1 : $0.0 < $1.0 }
            .map { "\($0.0)=\($0.1)" }.joined(separator: "&")
    }

    /// 构造与请求 Host 对应的签名值：主机转小写，IPv6 补方括号，非默认端口保留。
    /// HTTP 80 / HTTPS 443 不写入端口；上传入口本身只接受 HTTPS。
    static func canonicalHost(_ url: URL) -> String {
        var host = (url.host ?? "").lowercased()
        if host.contains(":"), !host.hasPrefix("[") { host = "[\(host)]" }
        if let port = url.port,
           !((url.scheme?.lowercased() == "https" && port == 443) ||
             (url.scheme?.lowercased() == "http" && port == 80)) { host += ":\(port)" }
        return host
    }

    /// 根据内存中的请求体计算哈希，再生成 PUT 请求头。
    ///
    /// - Parameters:
    ///   - url: 已经拼好的对象地址（path-style：`endpoint/bucket/key`）。
    ///   - method: 参与签名的 HTTP 方法；上传使用默认的 `PUT`。
    ///   - payload: 请求体，用于 `x-amz-content-sha256`。
    ///   - contentType: 对象的 MIME 类型，也会作为请求头参与签名。
    ///   - credentials: 桶、密钥、区域及可选会话令牌。
    ///   - date: 签名时间；测试可注入固定值，生产调用默认使用当前时间。
    /// - Returns: 应原样应用到请求上的签名头，包括 Authorization 和可选的会话令牌。
    static func headers(
        url: URL,
        method: String = "PUT",
        payload: Data,
        contentType: String,
        credentials: MovenS3Credentials,
        date: Date = Date()
    ) -> [String: String] {
        headers(url: url, method: method, payloadHash: sha256Hex(payload), contentType: contentType,
                credentials: credentials, date: date)
    }

    /// 使用已计算的请求体 SHA-256 构造签名，供文件分块哈希后的上传使用。
    /// 调用方必须保证上传的实际内容与 `payloadHash` 对应，否则服务端会拒绝请求。
    static func headers(
        url: URL,
        method: String = "PUT",
        payloadHash: String,
        contentType: String,
        credentials: MovenS3Credentials,
        date: Date = Date()
    ) -> [String: String] {
        let amzDate = amzDate(date)
        let stamp = dateStamp(date)
        let region = credentials.resolvedRegion
        // scope 约束签名可用的日期、区域和服务，与待签名字符串及 Authorization 一致。
        let scope = "\(stamp)/\(region)/s3/aws4_request"

        let host = canonicalHost(url)
        let contentType = contentType.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")

        // 规范请求只包含参与签名的头，名称必须小写并按字典序排列。
        // Content-Type 的空白会先规范化，再将同一结果写入实际 HTTP 请求。
        var headers = ["content-type": contentType, "host": host,
                       "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate]
        // 临时凭证的令牌既要随请求发送，也要参与规范头和 SignedHeaders。
        if !credentials.sessionToken.isEmpty { headers["x-amz-security-token"] = credentials.sessionToken }
        let names = headers.keys.sorted()
        let canonicalHeaders = names.map { "\($0):\(headers[$0]!)\n" }.joined()
        let signedHeaders = names.joined(separator: ";")

        // SigV4 依次签入方法、规范路径、规范查询、规范头、头名称和请求体哈希。
        let canonicalRequest = [
            method,
            canonicalURI(url),
            canonicalQuery(url),
            canonicalHeaders,
            signedHeaders,
            payloadHash,
        ].joined(separator: "\n")

        // 先对规范请求做 SHA-256，再将摘要放入待签名字符串，避免直接签入整个请求体。
        let stringToSign = [
            "AWS4-HMAC-SHA256",
            amzDate,
            scope,
            sha256Hex(Data(canonicalRequest.utf8)),
        ].joined(separator: "\n")

        // 从密钥依次派生日期、区域、服务和请求签名密钥；不直接发送 Secret Key。
        let kDate = hmacSHA256(key: Data("AWS4\(credentials.secretAccessKey)".utf8), message: stamp)
        let kRegion = hmacSHA256(key: kDate, message: region)
        let kService = hmacSHA256(key: kRegion, message: "s3")
        let kSigning = hmacSHA256(key: kService, message: "aws4_request")
        let signature = hmacSHA256(key: kSigning, message: stringToSign)
            .map { String(format: "%02x", $0) }.joined()

        headers["authorization"] = "AWS4-HMAC-SHA256 Credential=\(credentials.accessKeyID)/\(scope), SignedHeaders=\(signedHeaders), Signature=\(signature)"
        // 保持既有调用方使用的字段名；HTTP 头名称本身大小写不敏感。
        headers["Content-Type"] = headers.removeValue(forKey: "content-type")
        headers["Authorization"] = headers.removeValue(forKey: "authorization")
        return headers
    }
}

// MARK: - 上传

/// 对应 `plugins/s3_upload`：把文件直传到 S3 兼容存储。
///
/// Flutter 侧通过 MethodChannel 调原生（iOS 端其实是个空壳），这里用纯 Swift
/// 实现 SigV4 签名 + PUT，行为与插件在 Android 上的实现一致：
/// 成功返回对象路径（`/client_user/<uid>/avatar/<name>`），由调用方拼成公网 URL。
public struct MovenS3Uploader: Sendable {
    /// 上传进度回调（0...1），可能在任意线程触发；界面更新需自行切回主线程。
    /// 请求体发送阶段最多报告 0.999999，只有收到 HTTP 2xx 后才报告 1。
    public typealias ProgressHandler = @Sendable (Double) -> Void

    /// 每次上传创建独立 session；配置工厂也允许测试注入自定义 URLProtocol。
    private let configuration: @Sendable () -> URLSessionConfiguration

    public init(configuration: @escaping @Sendable () -> URLSessionConfiguration = { .ephemeral }) {
        self.configuration = configuration
    }

    /// 上传内存数据并返回以 `/` 开头的对象路径，与插件返回值保持一致。
    /// 先验证目标地址，再将数据哈希放到后台计算，最后用同一份数据发起 PUT。
    /// 返回路径只是对象 key，不包含桶名、endpoint 或 CDN 域名。
    ///
    /// - Parameters:
    ///   - data: 已加载到内存的完整对象内容。
    ///   - key: 桶内对象路径，例如 `client_user/42/avatar/a.jpg`。
    ///   - contentType: 对象的 MIME 类型，例如 `image/jpeg`。
    ///   - credentials: 上传凭证与目标桶配置。
    ///   - onProgress: 可选进度回调；回调线程不固定。
    /// - Throws: 配置、网络或服务端响应错误；调用任务取消时也可能抛出取消错误。
    @discardableResult
    public func upload(
        data: Data,
        key: String,
        contentType: String,
        credentials: MovenS3Credentials,
        onProgress: ProgressHandler? = nil
    ) async throws -> String {
        // 在计算大文件或数据的哈希前先验证上传地址和凭证，尽早失败。
        _ = try Self.objectURL(key: key, credentials: credentials)
        let hash = try await Self.hashInBackground { MovenS3Signer.sha256Hex(data) }
        return try await send(key: key, contentType: contentType, credentials: credentials,
                              payloadHash: hash, totalBytes: Int64(data.count), onProgress: onProgress) { session, request in
            try await session.upload(for: request, from: data)
        }
    }

    /// 分块计算哈希并从文件直接上传，避免应用将整个文件加载到内存。
    /// 计算哈希与 URLSession 发送是两次独立读取：调用方应在整个上传期间
    /// 保持文件存在且内容不变，否则签名与实际请求体可能不一致而被服务端拒绝。
    /// 文件大小用于进度兜底；无法读取大小时仍可上传，但进度取决于系统回调。
    /// `fileURL` 应指向本地文件；读取、签名或发送失败时会抛出对应错误，
    /// 调用方负责文件生命周期，上传器不会删除原文件。
    @discardableResult
    public func upload(fileURL: URL, key: String, contentType: String, credentials: MovenS3Credentials,
                onProgress: ProgressHandler? = nil) async throws -> String {
        _ = try Self.objectURL(key: key, credentials: credentials)
        let hash = try await Self.hashInBackground { try Self.sha256Hex(fileURL: fileURL) }
        let size = Int64((try? fileURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        return try await send(key: key, contentType: contentType, credentials: credentials,
                              payloadHash: hash, totalBytes: size, onProgress: onProgress) { session, request in
            try await session.upload(for: request, fromFile: fileURL)
        }
    }

    /// 把可能耗时的哈希工作移出调用方执行器，并将外层取消传递给后台任务。
    /// 后台返回后再检查一次取消，防止已取消的请求继续进入网络上传。
    private static func hashInBackground(_ body: @escaping @Sendable () throws -> String) async throws -> String {
        // 哈希计算不占用调用方的主线程；取消时同步通知后台任务并在返回前再次检查。
        let task = Task.detached(priority: .userInitiated) { try body() }
        return try await withTaskCancellationHandler {
            let hash = try await task.value
            try Task.checkCancellation()
            return hash
        } onCancel: { task.cancel() }
    }

    /// 每次读取最多 1 MiB，并在每次读取前响应取消；无论成功失败都关闭文件句柄。
    /// 返回的是整个文件的 SHA-256 十六进制摘要，并非各个分块摘要的拼接。
    static func sha256Hex(fileURL: URL) throws -> String {
        let file = try FileHandle(forReadingFrom: fileURL)
        defer { try? file.close() }
        var hash = SHA256()
        while true {
            // 文件哈希按 1 MiB 读取，并在每一块之间响应取消。
            try Task.checkCancellation()
            guard let chunk = try file.read(upToCount: 1024 * 1024), !chunk.isEmpty else { break }
            hash.update(data: chunk)
        }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// 构造实际 PUT 地址：`endpoint 的路径前缀 / bucket / object key`。
    /// 只接受带主机的 HTTPS 地址，并拒绝 URL 内嵌用户、密码或 fragment；
    /// endpoint 的查询参数保留给签名和请求。key 最多去掉一个开头的 `/`，
    /// 各路径段分别编码，避免空格、中文、`?` 或 `#` 被解释成 URL 结构。
    static func objectURL(key: String, credentials: MovenS3Credentials) throws -> URL {
        guard credentials.isConfigured else { throw MovenS3Error.notConfigured }
        // 上传地址必须使用 HTTPS，且不能在 URL 中携带用户信息或片段。
        guard var components = URLComponents(string: credentials.endpoint),
              components.scheme?.lowercased() == "https",
              let host = components.host, !host.isEmpty, components.user == nil,
              components.password == nil, components.fragment == nil else {
            throw MovenS3Error.invalidEndpoint(credentials.endpoint)
        }
        let objectKey = key.hasPrefix("/") ? String(key.dropFirst()) : key
        let basePath = components.percentEncodedPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let encodedKey = objectKey.split(separator: "/", omittingEmptySubsequences: false)
            .map { MovenS3Signer.uriEncode(String($0)) }.joined(separator: "/")
        components.percentEncodedPath = "/" + [basePath, MovenS3Signer.uriEncode(credentials.bucket), encodedKey]
            .filter { !$0.isEmpty }.joined(separator: "/")
        guard let url = components.url else { throw MovenS3Error.invalidEndpoint(credentials.endpoint) }
        return url
    }

    /// 共用的签名与发送流程：把预计算的请求体哈希写入签名，创建独立 session，
    /// 交给数据或文件上传闭包执行，并在结束时使 session 失效。
    /// 只有 HTTP 2xx 才返回对象路径并发送完成进度；其他状态保留状态码和最多
    /// 300 个字符的响应文本，网络异常和任务取消则由 URLSession 继续向上抛出。
    private func send(key: String, contentType: String, credentials: MovenS3Credentials,
                      payloadHash: String, totalBytes: Int64, onProgress: ProgressHandler?,
                      upload: (URLSession, URLRequest) async throws -> (Data, URLResponse)) async throws -> String {
        let url = try Self.objectURL(key: key, credentials: credentials)
        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.timeoutInterval = 60
        MovenS3Signer.headers(url: url, payloadHash: payloadHash, contentType: contentType,
                              credentials: credentials).forEach { request.setValue($1, forHTTPHeaderField: $0) }
        let delegate = MovenS3ProgressDelegate(totalBytes: totalBytes, onProgress: onProgress)
        let session = URLSession(configuration: configuration(), delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let (body, response) = try await upload(session, request)
        guard let http = response as? HTTPURLResponse else { throw MovenS3Error.emptyResponse }
        guard (200..<300).contains(http.statusCode) else {
            let text = String(data: body, encoding: .utf8) ?? ""
            throw MovenS3Error.badStatus(http.statusCode, String(text.prefix(300)))
        }
        // 仅在服务端接受请求后报告 100%，发送完请求体本身不代表上传成功。
        delegate.finish()
        return "/" + (key.hasPrefix("/") ? String(key.dropFirst()) : key)
    }

    /// 拼接供业务保存和访问的对象地址，它可能不同于上传地址。
    ///
    /// 优先使用 `publicBaseURL` 作为完整前缀；未配置时，已知云服务沿用
    /// `bucket.endpoint/key` 格式，自建网关、IP、端口、带路径前缀的服务和
    /// 带点的桶名使用 `endpoint/bucket/key` 格式。key 按路径段编码；默认
    /// 地址去掉上传 endpoint 的查询参数，显式公网前缀则保留它自己的查询参数。
    /// 若实际 CDN 地址不能由这些规则得到，需要由服务端提供公网前缀。
    public static func publicURL(path: String, credentials: MovenS3Credentials) -> URL? {
        let explicit = !credentials.publicBaseURL.isEmpty
        guard var components = URLComponents(string: explicit ? credentials.publicBaseURL : credentials.endpoint),
              components.scheme?.lowercased() == "https", let host = components.host?.lowercased(), !host.isEmpty,
              components.user == nil, components.password == nil, components.fragment == nil else { return nil }
        let key = path.hasPrefix("/") ? String(path.dropFirst()) : path
        let encodedKey = key.split(separator: "/", omittingEmptySubsequences: false)
            .map { MovenS3Signer.uriEncode(String($0)) }.joined(separator: "/")
        let basePath = components.percentEncodedPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if !explicit {
            // 上传地址的鉴权参数不应进入保存到用户资料的公开地址。
            components.percentEncodedQuery = nil
            let cloud = host.hasSuffix(".amazonaws.com") || host.hasSuffix(".amazonaws.com.cn") || host == "s3.amazonaws.com"
                || host.hasSuffix(".backblazeb2.com") || host.hasSuffix(".aliyuncs.com")
            // 带点的桶名不能可靠匹配云服务的通配 TLS 证书，改用路径式地址。
            if cloud && basePath.isEmpty && components.port == nil && !credentials.bucket.contains(".") {
                components.host = "\(credentials.bucket).\(host)"
            } else {
                components.percentEncodedPath = "/" + [basePath, MovenS3Signer.uriEncode(credentials.bucket)]
                    .filter { !$0.isEmpty }.joined(separator: "/")
            }
        }
        let prefix = components.percentEncodedPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        components.percentEncodedPath = "/" + [prefix, encodedKey].filter { !$0.isEmpty }.joined(separator: "/")
        return components.url
    }
}

/// 将 URLSession 的发送字节数转换为进度，并负责禁止自动重定向。
///
/// delegate 回调和上传完成处理可能来自不同线程；锁保护完成状态并串行调用
/// 进度闭包，避免成功后的迟到发送回调再次更新进度。`@unchecked Sendable`
/// 依赖这把锁保护可变状态；调用方仍须自行处理 UI 线程切换。
final class MovenS3ProgressDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var isFinished = false
    private let totalBytes: Int64
    private let onProgress: MovenS3Uploader.ProgressHandler?

    init(totalBytes: Int64 = 0, onProgress: MovenS3Uploader.ProgressHandler?) {
        self.totalBytes = totalBytes
        self.onProgress = onProgress
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didSendBodyData bytesSent: Int64,
        totalBytesSent: Int64,
        totalBytesExpectedToSend: Int64
    ) {
        // 优先采用系统提供的预期字节数；系统未知时使用调用方提供的文件 / 数据大小。
        let total = totalBytesExpectedToSend > 0 ? totalBytesExpectedToSend : totalBytes
        guard total > 0 else { return }
        report(Double(totalBytesSent) / Double(total))
    }

    func report(_ fraction: Double) {
        lock.withLock {
            guard !isFinished else { return }
            // 发送完成不代表服务器已接受；只在收到 2xx 后发送最终的 1。
            onProgress?(max(0, min(0.999_999, fraction)))
        }
    }

    /// 由上传流程在确认 HTTP 2xx 后调用；重复调用或之后的进度回调都会被忽略。
    func finish() {
        lock.withLock {
            guard !isFinished else { return }
            isFinished = true
            onProgress?(1)
        }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        // 重定向可能改变已签名的 Host / 路径，也不能转发认证信息到其他地址。
        completionHandler(nil)
    }
}
