# Security Policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue.

Use GitHub's [private vulnerability reporting](https://github.com/l1ratch/WSBridge-iOS/security/advisories/new)
(Security → Advisories → Report a vulnerability).

Please include what you did, what happened, and what you expected. A minimal
reproduction helps more than a long description.

## Scope

This repository contains an iOS Packet Tunnel Provider client. Areas worth
a careful look:

- the gateway protocol implementation (`Tunnel/WSClient.swift`, `Tunnel/MsgSplitter.swift`)
- the DNS path (`Tunnel/DNSForwarder.swift`, DoT/DoH/plain handling)
- secrets handling in `Tunnel/CFDomains.swift` and the front-domain list
- the config channel between app and tunnel extension (`providerConfiguration`)

## Not in scope

- The gateway you point the app at. This is a client; whoever runs the endpoint
  sees your traffic. Only use endpoints you trust.
- Traffic analysis by your network operator or ISP.
- Anything that requires a jailbroken device, or builds not produced either by
  this repository's CI or by a compiler you run yourself.

## Supported versions

Only the latest tagged release receives fixes. There are no long-lived branches;
`main` moves forward and releases are tagged from it.

## What this project does not do

It is a transport: it carries IP over a WebSocket. It does not contain
circumvention logic, does not ship a server, and does not include any
credential for a third-party service. Any endpoint you configure is yours to
choose and yours to trust.
