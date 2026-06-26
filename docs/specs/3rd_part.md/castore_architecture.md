# snix-castore Architecture

## Introduction

The `snix-castore` is a content-addressable blob store designed for efficient storage and transfer of large files. It achieves this through a sophisticated deduplication strategy based on content-defined chunking, cryptographic hashing, and a flexible object store backend.

## Core Concepts

- **Content-Addressable Storage (CAS)**: Blobs are addressed by a cryptographic hash of their contents, not by a user-defined name. This means that identical blobs will always have the same address, which is the foundation of the deduplication strategy.
- **Immutability**: Once a blob is written to the store, it cannot be modified. Any change to the content will result in a new blob with a new address.
- **Chunking**: Large files are broken down into smaller, variable-sized chunks. This allows for fine-grained deduplication and efficient network transfer.

## Deduplication Strategy

The deduplication strategy is implemented in several layers:

### 1. Content-Defined Chunking

`snix-castore` uses the `fastcdc` library to implement content-defined chunking. This means that the chunk boundaries are determined by the content of the file itself, rather than by fixed-size blocks. This has the significant advantage that if a small change is made to a large file, only the affected chunks will be modified, while the rest of the chunks will remain unchanged. This is particularly effective for source code, tarballs, and other file formats where changes are often localized.

### 2. Cryptographic Hashing

`snix-castore` uses the `blake3` cryptographic hash function to generate a unique digest for each chunk and for each blob (which is a manifest of chunks). `blake3` is a high-performance hash function that is well-suited for this use case.

### 3. Client-Side Deduplication

For small files, the `ConcurrentBlobUploader` implements a form of client-side deduplication. It reads the entire file into memory, hashes it, and then checks if a blob with the same hash already exists in the `BlobService` before uploading it. This avoids unnecessary network transfers for small, frequently-used files.

### 4. Server-Side Deduplication

For all files, the `ObjectStoreBlobService` implements server-side deduplication. Before uploading a chunk, it checks if a chunk with the same hash already exists in the object store. If it does, the upload is skipped. The same is true for blobs.

## Network Transfer

The `BlobService` API is designed to facilitate efficient network transfer.

- The `Stat` RPC allows a client to download the manifest of a large file without downloading the file itself. The manifest contains a list of the hashes of all the chunks in the file.
- The client can then compare the hashes in the manifest with the hashes of the chunks it already has locally.
- The client can then use the `Read` RPC to download only the missing chunks.

This significantly reduces the amount of data that needs to be transferred, especially for large files with a high degree of similarity to files that are already on the client.

## Storage Backend

`snix-castore` uses the `object_store` crate to provide a generic interface to a variety of object stores, including:

- Amazon S3
- Google Cloud Storage
- Azure Blob Storage
- Local filesystem

Chunks are compressed with `zstd` before being stored, which reduces storage costs.

## Data Layout

- **Blobs**: Blobs are stored at `${base_path}/blobs/b3/$digest_key`. They contain a serialized `StatBlobResponse` protobuf message, which is a manifest of the chunks that make up the blob.
- **Chunks**: Chunks are stored at `${base_path}/chunks/b3/$digest_key`. They contain the raw, `zstd`-compressed content of the chunk.
- **Sharding**: The `$digest_key` is sharded to avoid having too many files in one directory. The first two characters of the hex-encoded digest are used as a subdirectory.

## Conclusion

## Advanced Chunking Details

The chunking strategy is the most distinctive feature of `snix-castore`. It's designed to be both efficient and flexible, and it provides a level of verifiability that is not found in many other blob stores.

### Logical vs. Physical Chunking

A key innovation in `snix-castore` is the separation of logical and physical chunking.

- **Logical Chunking**: The `blake3` hash function is a tree hash, which means that it naturally divides the data into a tree of 1KiB chunks. This is the *logical* chunking of the data.
- **Physical Chunking**: The `fastcdc` library is used to split the data into variable-sized chunks for storage. This is the *physical* chunking of the data.

The root hash of the blob is the `blake3` hash of the *raw data*, not the hash of the physical chunks. This means that the physical chunking can be changed without changing the identity of the blob. This is a significant advantage over other content-addressable storage systems, where the chunking parameters are often embedded in the root hash.

### Verified Streaming

Because `blake3` is a tree hash, it's possible to verify the integrity of a chunk without having to download the entire file. The `Stat` RPC can return a BAO (BLAKE3 Authenticated Outboard) tree, which is a compact representation of the hash tree. The client can use this to verify the integrity of any chunk it downloads. This is a powerful feature that enables verified streaming and partial reads of large files.

### Overhead

The overhead of deduplication is primarily on the server, and it's done while streaming.

- **Streaming Chunking**: The `chunk_and_upload` function in `object_store.rs` uses an `AsyncStreamCDC` to chunk the incoming data as it's being read. This means that the server doesn't need to store the entire file in memory before it can start chunking and uploading it.
- **Concurrent Uploads**: The `fastcdc_chunk_uploader` function uploads chunks concurrently. This helps to improve performance by overlapping the chunking and uploading processes.
- **CPU Overhead**: The main overhead is the CPU cost of hashing and compressing the chunks. `blake3` is a very fast hash function, and `zstd` is a fast compression algorithm, so the overhead should be manageable for most workloads.
The `snix-castore` blob store is a well-designed system that leverages content-defined chunking, cryptographic hashing, and a flexible object store backend to provide efficient, deduplicated storage and transfer of large files. Its client-side and server-side deduplication strategies, combined with its network-efficient API, make it a powerful tool for a variety of use cases.
## Related Documents

- [Store API](src/store/api.md)
- [BlobStore Protocol](src/castore/blobstore-protocol.md)
- [BlobStore Chunking](src/castore/blobstore-chunking.md)