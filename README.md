# PoC-Find-Chrome-kTLSProtocolMethod

This code is a Proof of Concept code to download chrome.dll symbols from chromium symbols store by using dbghelp 
and symsrv API. Later it is possible to find the table of pointers: bssl::kTLSProtocolMethod. This table is usually 
hooked by malware to hijack browser communications. 

This table is defined here:

https://github.com/google/boringssl/blob/master/ssl/tls_method.cc

With the address of the table, it is possible to check the table's pointers to know if they are hooked.

I recommend to read the following article about downloading symbols with the API:

https://gregsplaceontheweb.wordpress.com/2015/08/15/how-to-download-windows-image-files-from-the-microsoft-symbol-server-using-c-and-dbghelp/

This PoC works for 64 bits, for 32 bits processes it is necesary to adapt it a bit.



