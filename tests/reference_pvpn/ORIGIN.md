These modules are test fixtures from https://github.com/qwj/python-vpn (master,
retrieved 2026-10-25). They are not imported by the installed client library.

Source Git blob IDs:

- crypto.py: f7f46e2b3c6e42b33eb61ceb086623c097b17c00
- enums.py: 8083965736f2ad828d105ce0aa7073d84dfacced
- message.py: 8a1b01019d80b4bbb237c49a9cdfe673c6233b89
- server.py: 53df0d58e5ed128dcd1f5fa6fc5005b367f672d8

crypto.py, enums.py and message.py are unmodified. server.py retains only
State, ChildSa, IKEv1Session and IKEv2Session; unrelated listeners/imports were
removed. The test adapter adds the IKEv2 USE_TRANSPORT_MODE response notification
because the reference server does not echo it. See the adjacent MIT license.

The server's rejection of an otherwise valid, fixed-width DH public value with
a leading zero byte was removed to avoid random test failures. No client
negotiation or key-derivation code is used in the reference server.
