# Product: rust-client (connect to existing Yggdrasil peers)

## Problem
Rust users who want to join the Yggdrasil encrypted IPv6 mesh today must shell out to or sidecar the Go implementation. There is no native Rust library that can peer with the existing network.

## Success metric
A Rust library consumer can establish a peer connection to an existing Go Yggdrasil node and exchange traffic, verified against a stock Go node build with zero patches to the Go side.

## Announcement — the blog post before the feature
`roots` is a native Rust client for the Yggdrasil network. Add it as a dependency, point it at any public or private peer URI, and your application joins the same encrypted IPv6 mesh as every existing node — no Go sidecar required. The first release focuses on peering with existing nodes over the standard peer URIs; more transports and platform integration follow.

## Screens
no UI (library crate; verification via integration test against a Go node, not screens)
