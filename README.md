# LspAgStorage

An iOS CocoaPods library for S3-compatible Signature V4 object uploads. It supports in-memory data, streaming file hashing, temporary session tokens, and upload progress.

## Requirements

- iOS 17.0 or later
- Swift 6
- CocoaPods with static frameworks

## Installation

After the package is published to CocoaPods Trunk:

```ruby
pod 'LspAgStorage', '0.1.1'
```

## Usage

```swift
import LspAgStorage

let credentials = MovenS3Credentials(
    bucket: bucket, endpoint: endpoint,
    accessKeyID: accessKeyID, secretAccessKey: secretAccessKey,
    region: region, sessionToken: sessionToken
)
let key = try await MovenS3Uploader().upload(
    fileURL: localFileURL, key: "avatars/example.jpg",
    contentType: "image/jpeg", credentials: credentials
) { progress in
    // Progress callbacks may arrive on a background thread.
}
let publicURL = MovenS3Uploader.publicURL(path: key, credentials: credentials)
```

The caller is responsible for obtaining and securing temporary credentials, choosing the correct region, and keeping the file unchanged throughout the upload. HTTPS is required; redirects are not followed. Progress reaches 100% only after an HTTP 2xx response.

## Validation

```sh
pod lib lint LspAgStorage.podspec --use-static-frameworks --platforms=ios
```

Do not commit real access keys or production configuration to this repository.

## License

Proprietary. Copyright Moven. All rights reserved.
