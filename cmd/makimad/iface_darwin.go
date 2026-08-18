package main

// macOS will not accept an arbitrary interface name: utun devices are numbered
// by the kernel and the name must be "utun" or "utunN". Passing the bare
// prefix asks for the next free one.
const defaultIface = "utun"
