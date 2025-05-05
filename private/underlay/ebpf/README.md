# LICENSE CONSIDERATIONS

The files bpf_helpers.h and bpf_helper_defs.h were copied here from
https://github.com/cilium/ebpf/tree/main/examples/headers . These files
themselves where obviously copied from
https://github.com/libbpf/libbpf/tree/master/src.

Whether from Cilium or libbpf, the files do not carry a copyright statement.
bpf_helper_defs.h does not reference any license. bpf_helpers.h  is offered
under either LGPL-2.1 OR BSD-2-Clause. We (The SCION Association) chose to
accept these files under the BSD-2-Clause license.

Cilium's version is accompanied by a generic copy of that licence. Libbpf's
version is accompanied by a modified copy of that license which includes a
copyright line by the libbpf authors. In the interest of transparency,
libbpf's license is reproduced below.

# Libbpf LICENSE

Valid-License-Identifier: BSD-2-Clause
SPDX-URL: https://spdx.org/licenses/BSD-2-Clause.html
Usage-Guide:
  To use the BSD 2-clause "Simplified" License put the following SPDX
  tag/value pair into a comment according to the placement guidelines in
  the licensing rules documentation:
    SPDX-License-Identifier: BSD-2-Clause
License-Text:

Copyright (c) 2015 The Libbpf Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
