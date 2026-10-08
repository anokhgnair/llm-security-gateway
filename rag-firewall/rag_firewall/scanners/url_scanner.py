# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import regex as re
from urllib.parse import urlparse
import ipaddress
URL_RE=re.compile(r"https?://[\w\-\.:%#@/\?=~\+,&]+", re.I)
class URLScanner:
    def __init__(self, allowlist=None, denylist=None):
        self.allowlist=set([d.lower() for d in (allowlist or [])])
        self.denylist=set([d.lower() for d in (denylist or [])])
    def scan(self, text, metadata):
        t=text or ""; out=[]
        for m in URL_RE.findall(t):
            host=(urlparse(m).hostname or "").lower()
            sev="low"; reason="url_found"
            # Flag IP literals (IPv4/IPv6)
            try:
                if host:
                    ipaddress.ip_address(host)
                    out.append({"scanner":"url","match":host,"severity":"high","reason":"ip_literal"})
                    # Do not continue; also evaluate allow/deny checks below
            except ValueError:
                pass
            # Flag punycode domains
            if host.startswith("xn--"):
                out.append({"scanner":"url","match":host,"severity":"high","reason":"punycode_host"})
            if self.denylist and any(host==d or host.endswith("."+d) for d in self.denylist):
                sev="high"; reason="denylist_domain"
            elif self.allowlist and not any(host==d or host.endswith("."+d) for d in self.allowlist):
                sev="high"; reason="non_allowlisted_domain"
            out.append({"scanner":"url","match":host or m,"severity":sev,"reason":reason})
        return out
