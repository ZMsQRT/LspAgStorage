import Foundation
import XCTest
@testable import LspAgStorage

final class LspAgStorageTests: XCTestCase {
    func testS3RegionInference() {
        XCTAssertEqual(MovenS3Credentials(bucket: "b", endpoint: "https://s3.amazonaws.com", accessKeyID: "k", secretAccessKey: "s").resolvedRegion, "us-east-1")
        XCTAssertEqual(MovenS3Credentials(bucket: "b", endpoint: "https://s3.eu-west-1.amazonaws.com", accessKeyID: "k", secretAccessKey: "s").resolvedRegion, "eu-west-1")
        XCTAssertEqual(MovenS3Credentials(bucket: "b", endpoint: "https://oss-cn-hangzhou.aliyuncs.com", accessKeyID: "k", secretAccessKey: "s").region, "")
    }

    func testS3PublicURLMatchesFlutterComposition() {
        let credentials = MovenS3Credentials(bucket: "mevon", endpoint: "https://s3.ap-east-1.amazonaws.com", accessKeyID: "k", secretAccessKey: "s")
        let url = MovenS3Uploader.publicURL(path: "/client_user/42/avatar/a.png", credentials: credentials)
        XCTAssertEqual(url?.absoluteString, "https://mevon.s3.ap-east-1.amazonaws.com/client_user/42/avatar/a.png")
    }

    func testS3SignatureIsDeterministic() {
        let credentials = MovenS3Credentials(bucket: "mevon", endpoint: "https://s3.ap-east-1.amazonaws.com", accessKeyID: "AKIDEXAMPLE", secretAccessKey: "secret")
        let url = URL(string: "https://s3.ap-east-1.amazonaws.com/mevon/client_user/42/avatar/a.png")!
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let payload = Data("hello".utf8)

        let first = MovenS3Signer.headers(url: url, payload: payload, contentType: "image/png", credentials: credentials, date: date)
        let second = MovenS3Signer.headers(url: url, payload: payload, contentType: "image/png", credentials: credentials, date: date)

        XCTAssertEqual(first, second, "同样的输入必须签出同样的结果")
        XCTAssertEqual(first["x-amz-content-sha256"], MovenS3Signer.sha256Hex(payload))
        XCTAssertTrue(first["Authorization"]?.hasPrefix("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") == true)
        XCTAssertTrue(first["Authorization"]?.contains("/ap-east-1/s3/aws4_request") == true)
    }

    func testS3SignatureMatchesIndependentAWSReferenceForEncodedURLAndTemporaryCredentials() throws {
        let credentials = MovenS3Credentials(bucket: "mybucket", endpoint: "https://s3.us-west-2.amazonaws.com:9443",
                                             accessKeyID: "AKIDEXAMPLE", secretAccessKey: "secret",
                                             sessionToken: "token123")
        let url = try XCTUnwrap(URL(string: "https://s3.us-west-2.amazonaws.com:9443/mybucket/%E4%B8%AD%20x%2B%23.png?z=2&a=hello%20world&a=1"))
        let headers = MovenS3Signer.headers(url: url, payload: Data("hello".utf8), contentType: "image/png",
                                            credentials: credentials, date: Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertEqual(MovenS3Signer.canonicalURI(url), "/mybucket/%E4%B8%AD%20x%2B%23.png")
        XCTAssertEqual(MovenS3Signer.canonicalQuery(url), "a=1&a=hello%20world&z=2")
        XCTAssertEqual(headers["host"], "s3.us-west-2.amazonaws.com:9443")
        XCTAssertEqual(headers["x-amz-security-token"], "token123")
        XCTAssertEqual(headers["Authorization"], "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20231114/us-west-2/s3/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=eb9daf46704256e4b382e433dc71301e25ab93e9336734d6514e8cee2fca1617")
    }

    func testS3CanonicalQueryPreservesDuplicatesAndLiteralPlus() throws {
        let url = try XCTUnwrap(URL(string: "https://storage.example.com/b/a%252Fb?uploadId=abc%2Fdef&acl&dup=z&dup=a&space=a+b"))
        XCTAssertEqual(MovenS3Signer.canonicalURI(url), "/b/a%252Fb")
        XCTAssertEqual(MovenS3Signer.canonicalQuery(url), "acl=&dup=a&dup=z&space=a%2Bb&uploadId=abc%2Fdef")
    }

    func testS3PublicAndUploadURLsPreservePathsAndEncodeObjectKeys() throws {
        var credentials = MovenS3Credentials(bucket: "bucket", endpoint: "https://storage.example.com:9000/api?z=2&a=1", accessKeyID: "k", secretAccessKey: "s")
        let key = "folder/中 +?#.jpg"
        XCTAssertEqual(try MovenS3Uploader.objectURL(key: key, credentials: credentials).absoluteString,
                       "https://storage.example.com:9000/api/bucket/folder/%E4%B8%AD%20%2B%3F%23.jpg?z=2&a=1")
        XCTAssertEqual(MovenS3Uploader.publicURL(path: key, credentials: credentials)?.absoluteString,
                       "https://storage.example.com:9000/api/bucket/folder/%E4%B8%AD%20%2B%3F%23.jpg")
        credentials.publicBaseURL = "https://cdn.example.com/assets"
        XCTAssertEqual(MovenS3Uploader.publicURL(path: key, credentials: credentials)?.absoluteString,
                       "https://cdn.example.com/assets/folder/%E4%B8%AD%20%2B%3F%23.jpg")
    }

    func testS3ProgressOnlyReachesOneAfterSuccess() {
        let recorder = S3ProgressRecorder()
        let delegate = MovenS3ProgressDelegate { recorder.append($0) }
        delegate.report(0.5)
        delegate.report(1)
        XCTAssertEqual(recorder.values, [0.5, 0.999_999])
        delegate.finish()
        delegate.report(0.7)
        delegate.finish()
        XCTAssertEqual(recorder.values, [0.5, 0.999_999, 1])
    }

    func testS3FileHashStreamsAndUploadReportsHTTPFailure() async throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("s3-test-\(UUID().uuidString)")
        let data = Data(repeating: 42, count: 1_100_000)
        try data.write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        XCTAssertEqual(try MovenS3Uploader.sha256Hex(fileURL: file), MovenS3Signer.sha256Hex(data))
        let uploader = MovenS3Uploader {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.protocolClasses = [S3TestHTTP.self]
            return configuration
        }
        let credentials = MovenS3Credentials(bucket: "bucket", endpoint: "https://storage.example.com", accessKeyID: "k", secretAccessKey: "s")
        let successProgress = S3ProgressRecorder()
        let result = try await uploader.upload(fileURL: file, key: "ok", contentType: "image/png", credentials: credentials) { successProgress.append($0) }
        XCTAssertEqual(result, "/ok")
        XCTAssertEqual(successProgress.values.last, 1)
        let failedProgress = S3ProgressRecorder()
        do {
            _ = try await uploader.upload(data: data, key: "reject", contentType: "image/png", credentials: credentials) { failedProgress.append($0) }
            XCTFail("HTTP 403 must fail")
        } catch let error as MovenS3Error {
            guard case .badStatus(403, _) = error else { return XCTFail("Unexpected error: \(error)") }
        }
        XCTAssertFalse(failedProgress.values.contains(1))
    }

}

private final class S3ProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [Double] = []
    var values: [Double] { lock.withLock { storage } }
    func append(_ value: Double) { lock.withLock { storage.append(value) } }
}

private final class S3TestHTTP: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let url = request.url else { return }
        let status = url.path.hasSuffix("/reject") ? 403 : 200
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if status == 403 { client?.urlProtocol(self, didLoad: Data("rejected".utf8)) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
