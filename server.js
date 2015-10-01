var express = require('express');
var http = require('http');
var WebSocket = require('ws');
var WebSocketServer = require('ws').Server;
var port = 8080;

var allowCrossDomain = function(req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
};

var app = express();
app.use(allowCrossDomain);
app.use(express.bodyParser());
app.use(express.cookieParser());
app.use(express.session({
    secret: '2234567890QWERTY'
}));
app.use(app.router);

var server = http.createServer(app)
server.listen(port)

var wss = new WebSocketServer({
    server: server
});

function createGuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0,
            v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function checkAuth(req, res, next) {
	
	console.log("check auth: ", req.body.token, req.body);
	var token = req.get("token");
	var user = req.get("user");
	console.log("token: ", token);
	console.log("user: ", user);
	console.log("tokens: ", tokens);
    if(typeof(token) !== 'undefined' && 
			typeof(user) !== 'undefined' &&
			typeof(tokens[user]) !== 'undefined' && 
			tokens[user].securityToken == token) {
		console.log("next()");
		next();
	} else {
		res.status(401);
		res.send('You are not authorized!');
	}
}

wss.broadcast = function(data) {
    for (var i in this.clients)
        this.clients[i].send(data);
};

var users = [];
var projects = [];
var components = [];
var project_components = [];
var vulnerabilities = [];
var vulnerability_states = [];
var tokens = {};

/************* sample data [start] *********************/
users.push({
    name: 'Lukas',
    password: "12345",
    email: "lsteiger@hsr.ch",
    userIdentifier: "1"
});
users.push({
    name: 'Janick',
    password: "12345",
    email: "jengeler@hsr.ch",
    userIdentifier: "2"
});
users.push({
    name: 'Mirko',
    password: "12345",
    email: "mirko.stocker@hsr.ch",
    userIdentifier: "3"
});

projects.push({
	id: 101,
	name: "Project 1",
	pl: 1
});	
projects.push({
	id: 102,
	name: "Project 2",
	pl: 1
});	
projects.push({
	id: 103,
	name: "Project 3",
	pl: 2
});	
projects.push({
	id: 104,
	name: "Project 4",
	pl: 2
});	

components.push({
	id: 201,
	name: ".NET Framework",
	version: "4.0",
	vendor: "Microsoft"
});
components.push({
	id: 202,
	name: "Adobe Reader",
	version: "9.0",
	vendor: "Adobe"
});
components.push({
	id: 203,
	name: "Zlib compression lib.",
	version: "1.1.4",
	vendor: "zlib.net"
});
components.push({
	id: 204,
	name: ".NET Framework",
	version: "3.5 SP1",
	vendor: "Microsoft"
});

project_components.push({ pid: 101, cid: 201 });
project_components.push({ pid: 101, cid: 202 });
project_components.push({ pid: 101, cid: 204 });
project_components.push({ pid: 102, cid: 202 });
project_components.push({ pid: 102, cid: 203 });
project_components.push({ pid: 103, cid: 201 });
project_components.push({ pid: 103, cid: 203 });
project_components.push({ pid: 103, cid: 204 });
project_components.push({ pid: 104, cid: 201 });

vulnerabilities.push({
	id: 1001,
	cid: 201,
	title: "Microsoft .NET Framework 4.x  JIT Compiler Vulnerability MS10-077 (KB2160841)",
	description: "A vulnerability has been reported in Microsoft .NET Framework, which can\r\nbe exploited by malicious people to compromise a vulnerable system.\r\nThe vulnerability is caused due to an unspecified error in the JIT\r\ncompiler while optimising code, which can be exploited to corrupt memory\r\nwhen a user visits a web page hosting a specially crafted XBAP (XAML\r\nbrowser application). \r\nSuccessful exploitation allows execution of arbitrary code.\r\nNOTE: This can also be exploited to break out of the ASP.NET sandbox with\r\na specially crafted ASP.NET application.\r\nThe vulnerability only affects Microsoft .NET Framework 4.0 on the x64 and\r\nItanium architectures.\r\n\r\nNote from vendor:\r\n\r\nThis security update resolves a privately reported vulnerability in Microsoft .NET Framework. The \r\nvulnerability could allow remote code execution on a client system if a user views a specially \r\ncrafted Web page using a Web browser that can run XAML Browser Applications (XBAPs). Users whose \r\naccounts are configured to have fewer user rights on the system could be less impacted than users \r\nwho operate with administrative user rights. The vulnerability could also allow remote code \r\nexecution on a server system running IIS, if that server allows processing ASP.NET pages and an \r\nattacker succeeds in uploading a specially crafted ASP.NET page to that server and then executes \r\nthe page, as could be the case in a Web hosting scenario.\r\n\r\nA remote code execution vulnerability exists in the Microsoft .NET Framework that can allow a \r\nspecially crafted Microsoft .NET application to access memory in an unsafe manner, leading to \r\narbitrary unmanaged code execution. This vulnerability only affects the x64 and Itanium \r\narchitectures.\r\n\r\n\r\nSystems affected:\r\nMicrosoft .NET Framework 4.x\r\n\r\nCheck if .NET 4.0 is isntalled on the system.\r\nFor Windows XP, only Windows XP Professional x64 Edition is affected, not non-x86 systems.\r\n\r\nA workaround is also available (patch installation recommended).\r\n",
	publish_date: "2010-10-12T20:15:07Z",
	cveId: "CVE-2010-3228",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-3228"
});
vulnerabilities.push({
	id: 1002,
	cid: 201,
	title: "Microsoft .NET Framework &lt; 4 beta 2 Security bypass - DUPLICATE - WITHDRAWN - Fixed in MS11-044",
	description: "The JIT compiler in Microsoft .NET Framework before 4 beta 2, when\r\nIsJITOptimizerDisabled is false, does not properly handle expressions\r\nrelated to null strings, which allows context-dependent attackers to bypass\r\nintended access restrictions in opportunistic circumstances by leveraging a\r\ncrafted application, as demonstrated by a C# application on the x86\r\nplatform.\r\n\r\nSystems affected:\r\nMicrosoft .NET Framework 2.x, 3.x, 4.x ",
	publish_date: "2011-05-11T10:49:32Z",
	cveId: "CVE-2011-1271",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-1271"
});
vulnerabilities.push({
	id: 1003,
	cid: 201,
	title: "Microsoft .NET 2.x 3.x 4.x Framework WinForms Memory Access Vulnerability MS12-038 (KB2706726, KB2686828, KB2686827, KB2686833, KB2686830, KB2686831)",
	description: "A vulnerability has been reported in Microsoft .NET Framework, which can be exploited \r\nby malicious people to compromise a user&#x27;s system.\r\n\r\nThe vulnerability is caused due to an error within the XAML Browser Application \r\n(XBAP) handling of Clipboard object data as unsafe memory access within \r\nSystem.Windows.Forms.Clipboard allows controlling a function pointer. \r\n\r\nSuccessful exploitation allows execution of arbitrary code, but requires a browser \r\nthat runs XAML Browser Applications (XBAPs). \r\n\r\nVendor note:\r\nThis security update resolves one privately reported vulnerability in the Microsoft \r\n.NET Framework. The vulnerability could allow remote code execution on a client \r\nsystem if a user views a specially crafted webpage using a web browser that can run \r\nXAML Browser Applications (XBAPs). Users whose accounts are configured to have fewer \r\nuser rights on the system could be less impacted than users who operate with \r\nadministrative user rights. The vulnerability could also be used by Windows .NET \r\nFramework applications to bypass Code Access Security (CAS) restrictions. In a web \r\nbrowsing attack scenario, an attacker could host a website that contains a webpage \r\nthat is used to exploit this vulnerability. In addition, compromised websites and \r\nwebsites that accept or host user-provided content or advertisements could contain \r\nspecially crafted content that could exploit this vulnerability. In all cases, \r\nhowever, an attacker would have no way to force users to visit these websites. \r\nInstead, an attacker would have to convince users to visit the website, typically by \r\ngetting them to click a link in an email message or Instant Messenger message that \r\ntakes users to the attacker&#x27;s website. \r\nThis security update is rated Critical for Microsoft .NET Framework 2.0 Service Pack \r\n2, Microsoft .NET Framework 3.5.1, and Microsoft .NET Framework 4 on all supported \r\neditions of Microsoft Windows. \r\nhis security update is rated Critical for Microsoft .NET Framework 2.0 Service Pack \r\n2, Microsoft .NET Framework 3.5.1, and Microsoft .NET Framework 4 on all supported \r\neditions of Microsoft Windows. \r\nThe security update addresses the vulnerability by correcting the manner in which the \r\n.NET Framework validates data passed to function pointers. \r\nCVE-2012-1855\r\n\r\nA remote code execution vulnerability exists in the Microsoft .NET Framework due to \r\nthe improper execution of a function pointer. An attacker who successfully exploited \r\nthis vulnerability could take complete control of an affected system. An attacker \r\ncould then install programs; view, change, or delete data; or create new accounts \r\nwith full user rights. Users whose accounts are configured to have fewer user rights \r\non the system could be less impacted than users who operate with administrative user \r\nrights. \r\nMitigation refers to a setting, common configuration, or general best-practice, \r\nexisting in a default state that could reduce the severity of exploitation of a \r\nvulnerability. The following mitigating factors may be helpful in your situation: \r\n\r\n* In a web browsing attack scenario, an attacker could host a website that contains a \r\nwebpage that is used to exploit this vulnerability. In addition, compromised websites \r\nand websites that accept or host user-provided content or advertisements could \r\ncontain specially crafted content that could exploit this vulnerability. In all \r\ncases, however, an attacker would have no way to force users to visit these websites. \r\nInstead, an attacker would have to convince users to visit the website, typically by \r\ngetting them to click a link in an email message or Instant Messenger message that \r\ntakes users to the attacker&#x27;s website. * By default, Internet Explorer on Windows \r\nServer 2003, Windows Server 2008, and Windows Server 2008 R2 runs in a restricted \r\nmode that is known as Enhanced Security Configuration. This mode mitigates this \r\nvulnerability only on Windows Server 2008 and Windows Server 2008 R2, and only in a \r\nweb browsing attack scenario. See the FAQ section of this vulnerability for more \r\ninformation about Internet Explorer Enhanced Security Configuration. * Standard .NET \r\nFramework applications are not affected by this vulnerability. Only specially crafted \r\n.NET Framework applications could exploit this vulnerability. \r\n\r\nSystems affected:\r\nMicrosoft .NET Framework 2.x\r\nMicrosoft .NET Framework 3.x\r\nMicrosoft .NET Framework 4.x\r\n\r\nCheck vendor advisory to affected details as some SP&#x27;s are not affected.",
	publish_date: "2012-06-12T21:14:56Z",
	cveId: "CVE-2012-1855",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-1855"
});	

vulnerabilities.push({
	id: 1004,
	cid: 202,
	title: "Adobe Reader/Acrobat Unspecified Buffer Overflow Vulnerability APSA09-01",
	description: "A vulnerability has been reported in Adobe Reader/Acrobat, which can be exploited by malicious people to compromise a user&#x27;s system.The vulnerability is caused due to an unspecified error and can be exploited to cause a buffer overflow. No further information is available. \r\n\r\nSuccessful exploitation allows execution of arbitrary code.\r\n\r\nNOTE: Reportedly, the vulnerability is currently being actively exploited.Adobe is planning to release updates to Adobe Reader and Acrobat to resolve the relevant security issue. Adobe expects to make available an update for Adobe Reader 9 and Acrobat 9 by March 11th, 2009. Updates for Adobe Reader 8 and Acrobat 8 will follow soon after, with Adobe Reader 7 and Acrobat 7 updates to follow. In the meantime, Adobe is in contact with anti-virus vendors, including McAfee and Symantec, on this issue in order to ensure the security of our mutual customers. A security bulletin will be published on http://www.adobe.com/support/security as soon as product updates are available.\r\n\r\n\r\n\r\n",
	publish_date: "2009-03-19T12:05:31Z",
	cveId: "CVE-2009-0658",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-0658"
});	
vulnerabilities.push({
	id: 1005,
	cid: 202,
	title: "Adobe Reader/Acrobat Multiple Vulnerabilities",
	description: "Some vulnerabilities have been reported in Adobe Reader/Acrobat, which can be exploited by malicious people to compromise a user&#x27;s system.\r\n\r\n1) An array indexing error in the processing of JBIG2 streams can be exploited to corrupt arbitrary memory via a specially crafted PDF file. \r\n\r\nSuccessful exploitation allows execution of arbitrary code.\r\n\r\nNOTE: This vulnerability is currently being actively exploited.\r\n\r\n2) An error when processing JavaScript calls to the &quot;getIcon()&quot; method of a &quot;Collab&quot; object can be exploited to cause a stack-based buffer overflow via a specially crafted argument.\r\n\r\nNOTE: This is already fixed in Adobe Acrobat/Reader 8.1.3.\r\n\r\n3) A boundary error in the processing of JBIG2 streams can be exploited to cause a heap-based buffer overflow via a specially crafted PDF file containing a malformed JBIG2 symbol dictionary segment.\r\n\r\n4) A boundary error in the processing of JBIG2 streams can be exploited to cause a heap-based buffer overflow via a specially crafted PDF file.\r\n\r\n5) Two unspecified input validation errors in the processing of JBIG2 streams can be exploited to potentially execute arbitrary code.\r\n",
	publish_date: "2009-03-19T13:56:24Z",
	cveId: "CVE-2009-0193",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-0193"
});
vulnerabilities.push({
	id: 1006,
	cid: 202,
	title: "APSB09-07: Adobe Reader/Acrobat Multiple Vulnerabilities",
	description: "Some vulnerabilities have been reported in Adobe Reader and Acrobat, which can be exploited by malicious people to compromise a user&#x27;s system.\r\n\r\n1) A boundary error in the processing of Huffman encoded JBIG2 text region segments can be exploited to cause a heap-based buffer overflow and potentially execute arbitrary code via a specially crafted PDF document.\r\n\r\nThe vulnerability is confirmed in version 9.1.0. Other versions may also be affected.\r\n\r\n2) An error can be exploited to cause a stack-based buffer overflow and potentially execute arbitrary code.\r\n\r\n3) An integer overflow error can be exploited to potentially execute arbitrary code. \r\n\r\n4) An unspecified error can be exploited to corrupt memory and potentially execute arbitrary code.\r\n\r\n5) An error in the processing of JBIG2 data can be exploited to corrupt memory and potentially execute arbitrary code.\r\n\r\n6) Another unspecified error can be exploited to corrupt memory and potentially execute arbitrary code.\r\n\r\n7) Multiple errors in the JBIG2 filter can be exploited to cause heap-based buffer overflows and potentially execute arbitrary code.\r\n\r\n8) An error in the JBIG2 filter can be exploited to cause a heap-based buffer overflow and potentially execute arbitrary code.\r\n\r\n9) Multiple errors can be exploited to cause heap-based buffer overflows and potentially execute arbitrary code.\r\n",
	publish_date: "2009-06-10T10:17:57Z",
	cveId: "CVE-2009-0198",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-0198"
});
vulnerabilities.push({
	id: 1007,
	cid: 202,
	title: "Adobe getPlus shipped with Acrobat Reader 9.x DLM Insecure Default Directory Permissions",
	description: "A security issue has been discovered in Adobe getPlus DLM, which can be exploited by malicious, local users to gain escalated privileges.\r\n\r\nThe security issue is caused due to the application setting insecure default permissions on the &quot;NOS&quot; installation directory. This can be exploited to gain escalated privileges by e.g. replacing the getPlus_HelperSvc.exe service binary.\r\n\r\nThe security issue is confirmed in version 1.6.2.36. Other versions may also be affected.\r\n\r\nSolution:\r\nRemove unprivileged access from the permissions set on the &quot;NOS&quot; directory.",
	publish_date: "2009-07-21T11:21:49Z",
	cveId: "CVE-2009-2564",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-2564"
});

vulnerabilities.push({
	id: 1008,
	cid: 203,
	title: "ZLib &lt; 1.2.3 - Buffer-Overflow in ZLib",
	description: "Zlib is prone to a buffer-overflow vulnerability because the application fails to properly validate input data before using it in a memory copy operation. \r\n\r\nIn certain circumstances, malformed input data during decompression may cause a memory buffer to overflow. This may result in denial-of-service conditions or may allow remote code to execute in the context of applications that use the affected library. \r\n\r\n \r\n",
	publish_date: "2006-06-12T22:00:00Z",
	cveId: "",
	nveUrl: ""
});
vulnerabilities.push({
	id: 1009,
	cid: 203,
	title: "Zlib Compression Library gzprintf() Buffer Overrun Vulnerability",
	description: "A vulnerability has been reported in the zlib compression library. Due to the use of vsprintf() by an internal Zlib function, it may be possible to trigger a condition under which memory corruption will occur. This buffer overrun exists due to insufficient bounds checking of user-supplied data, supplied to the gzprintf() function. \r\n\r\nSuccessful exploitation of this vulnerability may allow an attacker to execute arbitrary instructions.\r\n\r\nIt should be noted that only zlib 1.1.4 has been reported vulnerable to this issue. It is not yet known whether earlier versions are also affected. \r\n",
	publish_date: "2007-04-04T22:00:00Z",
	cveId: "",
	nveUrl: ""
});

vulnerabilities.push({
	id: 1010,
	cid: 204,
	title: "Microsoft .NET Framework 1.x, 2.x, 3.x  Multiple Vulnerabilities MS09-061 (KB974378, KB953297, KB953300, KB974417, KB953295, KB953298, KB974468, KB974292, KB974467, KB974291, KB974469, KB974470)",
	description: "Some vulnerabilities have been reported in Microsoft .NET Framework, which can be exploited by malicious people to compromise a vulnerable system.\r\n\r\n1) An unspecified error can be exploited to obtain a managed pointer to stack memory, which can be exploited to execute arbitrary code e.g. via a specially crafted ASP .NET application, or XBAP (XAML browser application).\r\n\r\n2) An error in the verification of Microsoft .NET verifiable code can be exploited to bypass a type equality check and execute arbitrary code e.g. via a specially crafted ASP .NET application or XBAP.\r\n\r\n3) An error exists in the Microsoft .NET Common Language Runtime (CLR) in the handling of interfaces. This can be exploited to corrupt memory and execute arbitrary code e.g. via a specially crafted ASP .NET application or XBAP.\r\n",
	publish_date: "2009-10-14T08:27:15Z",
	cveId: "CVE-2009-0090",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-0090"
});
vulnerabilities.push({
	id: 1011,
	cid: 204,
	title: "Microsoft .NET Framework / Silverlight Code Execution Vulnerabilities MS10-060 (KB978464, KB982926, KB983582, KB983583, KB983587, KB983588, KB983589, KB983590, KB2265906)",
	description: "Some vulnerabilities have been reported in Microsoft .NET Framework and Silverlight, which can be \r\nexploited by malicious people to compromise a vulnerable system.\r\n\r\n1) An error in the way Silverlight handles pointers can be exploited to corrupt memory by tricking \r\na user into visiting a web site containing specially crafted Silverlight content.\r\n\r\nSuccessful exploitation allows execution of arbitrary code.\r\n\r\nNOTE: This vulnerability affects Silverlight 3 only.\r\n\r\n2) An error in the .NET Framework when the CLR (Common Language Runtime) handles delegates to \r\nvirtual methods can be exploited by a specially crafted .NET application or Silverlight application \r\nto execute arbitrary unmanaged code.\r\n\r\n\r\n\t\t\t\t\t\r\nSystems affected:\r\nMicrosoft .NET Framework 2.x\r\nMicrosoft .NET Framework 3.x\r\nMicrosoft Silverlight 2.x\r\nMicrosoft Silverlight 3.x\r\n\r\nNOTE: Version 3.0 of the .NET Framework is included with Windows Server 2008 and Windows Vista. \r\nVersion 3.5 is included with Windows 7, and can also be installed on Windows XP and the Windows \r\n2008Server 2003 family of operating systems.\r\n\r\nCheck vendor link for explanation of fixes for x64 based systems\r\n",
	publish_date: "2010-08-10T20:12:22Z",
	cveId: "CVE-2010-0019",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-0019"
});
vulnerabilities.push({
	id: 1012,
	cid: 204,
	title: "Microsoft .NET 2.x, 3.x, 4.x Framework JIT Compiler Stack Corruption Vulnerability MS11-028 (KB2446704, KB2446708, KB2446709, KB2446710, KB2449741, KB2449742):",
	description: "A vulnerability has been reported in Microsoft .NET Framework, which can\r\nbe exploited by malicious people to compromise a vulnerable system.\r\n\r\nThe vulnerability is caused due to an error in the x86 JIT compiler when\r\ncompiling certain function calls. This can be exploited to corrupt the\r\nstack via a specially crafted XAML Browser Application (XBAP).\r\n\r\nSuccessful exploitation allows execution of arbitrary code.\r\n\r\nThis security update resolves a publicly disclosed vulnerability in Microsoft .NET Framework. The vulnerability could allow remote code execution on a client system if a user views a specially crafted Web page using a Web browser that can run XAML Browser Applications (XBAPs). Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights. The vulnerability could also allow remote code execution on a server system running IIS, if that server allows processing ASP.NET pages and an attacker succeeds in uploading a specially crafted ASP.NET page to that server and then executes the page, as could be the case in a Web hosting scenario. This vulnerability could also be used by Windows .NET applications to bypass Code Access Security (CAS) restrictions.\r\n\r\nA remote code execution vulnerability exists in the way that Microsoft .NET Framework handles certain function calls. An attacker who successfully exploited this vulnerability could take complete control of an affected system. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights. Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights.\r\n\r\nTo view this vulnerability as a standard entry in the Common Vulnerabilities and Exposures list, see CVE-2010-3958.\r\n\r\nMitigation refers to a setting, common configuration, or general best-practice, existing in a default state, that could reduce the severity of exploitation of a vulnerability. The following mitigating factors may be helpful in your situation:\r\n\t\r\n\r\nIn a Web-based attack scenario, an attacker could host a Web site that contains a Web page that is used to exploit this vulnerability. In addition, compromised Web sites and Web sites that accept or host user-provided content or advertisements could contain specially crafted content that could exploit this vulnerability. In all cases, however, an attacker would have no way to force users to visit these Web sites. Instead, an attacker would have to convince users to visit the Web site, typically by getting them to click a link in an e-mail message or Instant Messenger message that takes users to the attacker’s Web site.\r\n\t\r\n\r\nBy default, Internet Explorer on Windows Server 2003, Windows Server 2008, and Windows Server 2008 R2 runs in a restricted mode that is known as Enhanced Security Configuration. This mode mitigates this vulnerability only on Windows Server 2008 and Windows Server 2008 R2, and only in a Web-based attack scenario. See the FAQ section of this vulnerability for more information about Internet Explorer Enhanced Security Configuration.\r\n\t\r\n\r\nAn attacker who successfully exploited this vulnerability could gain the same user rights as the local user or the user account of ASP.NET. Users or accounts that are configured to have fewer user rights on the system could be less impacted than users or accounts that operate with administrative user rights.\r\n\t\r\n\r\nIn a Web-hosting scenario, an attacker must have permission to upload arbitrary ASP.NET pages to a Web site and ASP.NET must be installed on that Web server. In default configuration, an anonymous user cannot upload and run Microsoft .NET code on an Internet Information Server (IIS).\r\n\t\r\n\r\nStandard .NET Framework applications are not affected by this vulnerability. Only specially crafted .NET Framework applications could exploit this vulnerability.\r\n\r\nExtended Solution:\r\nAs a workaround disable XAML Browser Applications in Internet Explorer\r\n(please see the vendor&#x27;s advisory for details).\r\n\r\nSystems affected:\r\nMicrosoft .NET Framework 2.x\r\nMicrosoft .NET Framework 3.x\r\nMicrosoft .NET Framework 4.x\r\n\r\nNote: Version 3.0 of the .NET Framework is included with Windows Server 2008 and Windows Vista. Version 3.5 is included with Windows 7, and can also be installed on Windows XP and the Windows Server 2003 family of operating systems.",
	publish_date: "2011-04-12T20:04:30Z",
	cveId: "CVE-2010-3958",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-3958"
});
vulnerabilities.push({
	id: 1013,
	cid: 204,
	title: "Microsoft .NET Framework &lt; 4 beta 2 Security bypass - DUPLICATE - WITHDRAWN - Fixed in MS11-044",
	description: "The JIT compiler in Microsoft .NET Framework before 4 beta 2, when\r\nIsJITOptimizerDisabled is false, does not properly handle expressions\r\nrelated to null strings, which allows context-dependent attackers to bypass\r\nintended access restrictions in opportunistic circumstances by leveraging a\r\ncrafted application, as demonstrated by a C# application on the x86\r\nplatform.\r\n\r\nSystems affected:\r\nMicrosoft .NET Framework 2.x, 3.x, 4.x ",
	publish_date: "2011-05-11T10:49:32Z",
	cveId: "CVE-2011-1271",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-1271"
});
vulnerabilities.push({
	id: 1014,
	cid: 204,
	title: "Microsoft .NET Framework 2.x, 3.x, 4.x Socket Restriction Bypass Vulnerability MS11-069 KB2567951, KB2539631, KB2539633, KB2539634, KB2539635, KB2539636",
	description: "A vulnerability has been reported in Microsoft .NET Framework, which can\r\nbe exploited by malicious people to bypass certain security restrictions or\r\ngain knowledge of sensitive information.\r\n\r\nThe vulnerability is caused due to an error when validating the trust\r\nlevel within the System.Net.Sockets namespace and can be exploited to\r\nbypass CAS (Code Access Security) restrictions or disclose information via\r\na specially crafted web page viewed using a browser that supports XBAPs (XAML Browser Applications).\r\n\r\nExtended Solution:\r\nAs a workaround, disable XAML browser applications in Internet Explorer.\r\nPlease see the Microsoft security bulletin for details.\r\n\r\nPriority two if internet access is available.\r\nPriority three if NO internet access is available.\r\n\r\nVendor note:\r\nThis security update resolves a privately reported vulnerability in Microsoft .NET Framework. The vulnerability could allow information disclosure if a user views a specially crafted Web page using a Web browser that can run XAML Browser Applications (XBAPs). In a Web-based attack scenario, an attacker could host a Web site that contains a Web page that is used to exploit this vulnerability. In addition, compromised Web sites and Web sites that accept or host user-provided content or advertisements could contain specially crafted content that could exploit this vulnerability. In all cases, however, an attacker would have no way to force users to visit these Web sites. Instead, an attacker would have to convince users to visit the Web site, typically by getting them to click a link in an e-mail message or Instant Messenger message that takes users to the attacker&#x27;s Web site. This vulnerability could also be used by Windows .NET applications to bypass Code Access Security (CAS) restrictions.\r\n\r\nThis security update is rated Moderate for Microsoft .NET Framework 2.0 Service Pack 2, Microsoft .NET Framework 3.5.1, and Microsoft .NET Framework 4 on all supported editions of Microsoft Windows.\r\n\r\nWhat is the difference between .NET Framework 4 and .NET Framework 4 Client Profile? \r\nThe .NET Framework version 4 redistributable packages are available in two profiles: .NET Framework 4 and .NET Framework 4 Client Profile. The .NET Framework 4 Client Profile is a subset of the .NET Framework 4 profile that is optimized for client applications. It provides functionality for most client applications, including Windows Presentation Foundation (WPF), Windows Forms, Windows Communication Foundation (WCF), and ClickOnce features. This enables faster deployment and a smaller install package for applications that target the .NET Framework 4 Client Profile. \r\n\r\n Socket Restriction Bypass Vulnerability - CVE-2011-1978 \r\n\r\nAn information disclosure vulnerability exists in the way that .NET Framework improperly validates the trust level within the System.Net.Sockets namespace. An attacker who successfully exploited this vulnerability would be able to access information not intended to be exposed. Additionally, this vulnerability could be used by an attacker to direct network traffic from a victim&#x27;s system to other network resources the victim can access. This could allow an attacker to perform a denial of service to any system the victim&#x27;s system can access or use the victim&#x27;s system to perform scanning of network resources available to the victim. Note that this vulnerability would not allow an attacker to execute code or to elevate their user rights directly, but it could be used to produce information that could be used to try to further compromise the affected system.\r\n\r\n\r\n Mitigating Factors for Socket Restriction Bypass Vulnerability - CVE-2011-1978 \r\n\r\nMitigation refers to a setting, common configuration, or general best-practice, existing in a default state, that could reduce the severity of exploitation of a vulnerability. The following mitigating factors may be helpful in your situation: \r\n\r\n• In a Web-based attack scenario, an attacker could host a Web site that contains a Web page that is used to exploit this vulnerability. In addition, compromised Web sites and Web sites that accept or host user-provided content or advertisements could contain specially crafted content that could exploit this vulnerability. In all cases, however, an attacker would have no way to force users to visit these Web sites. Instead, an attacker would have to convince users to visit the Web site, typically by getting them to click a link in an e-mail message or Instant Messenger message that takes users to the attacker&#x27;s Web site.\r\n \r\n• By default, Internet Explorer on Windows Server 2003, Windows Server 2008, and Windows Server 2008 R2 runs in a restricted mode that is known as Enhanced Security Configuration. This mode mitigates this vulnerability only on Windows Server 2008 and Windows Server 2008 R2, and only in a Web-based attack scenario. See the FAQ section of this vulnerability for more information about Internet Explorer Enhanced Security Configuration.\r\n \r\n• In a Web-hosting scenario, an attacker must have permission to upload arbitrary ASP.NET pages to a Web site and ASP.NET must be installed on that Web server. In default configuration, an anonymous user cannot upload and run Microsoft .NET code on an Internet Information Server (IIS).\r\n \r\n• Customers who have installed KB2562394 cannot be exploited without user interaction. This update, made available through MS11-044, prevents ClickOnce applications in the Internet zone from executing without prompting the user. Customers who have not installed KB2562394 will not receive a dialog box if the application is not using any more than Internet-only permissions. See KB2562394 for further information on this feature.\r\n\r\n\r\nSystems affected:\r\nMicrosoft .NET Framework 2.x\r\nMicrosoft .NET Framework 3.x\r\nMicrosoft .NET Framework 4.x",
	publish_date: "2011-08-10T13:21:32Z",
	cveId: "CVE-2011-1978",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-1978"
});
vulnerabilities.push({
	id: 1015,
	cid: 204,
	title: "Microsoft .NET framework Vulnerability in ASP.NET Could Allow Denial of Service KB2638420 KB2656351 KB2656352 KB2656353 KB2656355 KB2656356 KB2656358 KB2656362 KB2657424 MS11-100",
	description: "Four vulnerabilities have been reported in Microsoft .NET Framework, which\r\ncan be exploited by malicious people to cause a DoS (Denial of Service),\r\nconduct spoofing attacks, or bypass certain security restrictions.\r\n\r\n1) An error within ASP.NET when hashing form posts and updating a hash\r\ntable can be exploited to cause a hash collision resulting in high CPU\r\nconsumption via a specially crafted form sent in a HTTP POST request.\r\nSuccessful exploitation of this vulnerability requires that a site allows\r\n&quot;application/x-www-form-urlencoded&quot; or &quot;multipart/form-data&quot; HTTP content\r\ntypes.\r\n\r\n2) An error in the verification of return URLs during the forms\r\nauthentication process can be exploited to redirect a user to an arbitrary\r\nwebsite without the user&#x27;s knowledge to e.g. conduct phishing attacks.\r\n\r\nSuccessful exploitation of this vulnerability requires that &quot;Forms\r\nAuthentication&quot; is configured per-application to be enabled.\r\n\r\n3) An error in the authentication process when handling specially crafted\r\nusernames can be exploited to access arbitrary users&#x27; accounts to an\r\nASP.NET application via a specially crafted web request.\r\n\r\nSuccessful exploitation of this vulnerability requires that &quot;Forms\r\nAuthentication&quot; is configured per-application to be enabled and that a user\r\ncan register an account on the ASP.NET application and knows of a target\r\nuser&#x27;s account name.\r\n\r\n4) An error in the handling of cached content when &quot;Forms Authentication&quot;\r\nis used with sliding expiry can be exploited to execute arbitrary commands\r\nin context of a target user tricked into following a specially crafted\r\nlink.\r\n\r\nSuccessful exploitation of this vulnerability requires that ASP.NET\r\nresponses are cached through use of the &quot;OutputCache&quot; directive.\r\n\r\n\r\nVendor information:\r\n\r\nThis security update resolves one publicly disclosed vulnerability and three \r\nprivately reported vulnerabilities in Microsoft .NET Framework. The most severe \r\nof these vulnerabilities could allow elevation of privilege if an unauthenticated \r\nattacker sends a specially crafted web request to the target site. An attacker who \r\nsuccessfully exploited this vulnerability could take any action in the context of \r\nan existing account on the ASP.NET site, including executing arbitrary commands. \r\nIn order to exploit this vulnerability, an attacker must be able to register an \r\naccount on the ASP.NET site, and must know an existing user name.\r\n\r\nThe security update addresses the vulnerabilities by correcting how the .NET \r\nFramework handles specially crafted requests, and how the ASP.NET Framework \r\nauthenticates users and handles cached content.\r\n\r\n\r\nThere are two updates listed for the version of the Microsoft .NET Framework installed \r\non my system. Do I need to install both updates? \r\nYes. Customers should apply all updates offered for the software installed on their systems.\r\n\r\nDo I need to install these security updates in a particular sequence? \r\nNo. Multiple updates for one version of the .NET Framework can be applied in any sequence. \r\nWe recommend that multiple updates for different versions of the .NET Framework be applied \r\nin sequence from lowest version number to highest, however that sequence is not required.\r\n\r\nI have .NET Framework 3.0 Service Pack 2 installed; this version is not listed among the \r\naffected software in this bulletin. Do I need to install an update? \r\nThis bulletin describes a vulnerability in the .NET Framework 2.0 feature layer and the \r\n.NET Framework 4. The .NET Framework 3.0 Service Pack 2 installer chains in the .NET \r\nFramework 2.0 Service Pack 2 setup, so installing the former also installs the latter. \r\nTherefore, customers who have the .NET Framework 3.0 Service Pack 2 installed need to \r\ninstall security updates for the .NET Framework 2.0 Service Pack 2.\r\n\r\nI have .NET Framework 3.5 Service Pack 1 installed. Do I need to install any additional \r\nupdates? \r\nThis bulletin describes a vulnerability in the .NET Framework 2.0 feature layer and the \r\n.NET Framework 4. The .NET Framework 3.5 Service Pack 1 installer chains in both the .NET \r\nFramework 2.0 Service Pack 2 setup and the .NET Framework 3.0 Service Pack 2 setup. \r\nTherefore, customers who have the.NET Framework 3.5 Service Pack 1 installed also need \r\nto install security updates for the .NET Framework 2.0 Service Pack 2.\r\n\r\n\r\n\r\nSystems affected:\r\nMicrosoft .NET framework\r\n\r\nNote: .NET Framework is installed as default on Windows 2003 2008 7 XP Vista\r\n",
	publish_date: "2011-12-28T16:38:32Z",
	cveId: "CVE-2011-3414",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-3414"
});
vulnerabilities.push({
	id: 1016,
	cid: 204,
	title: "Microsoft .NET Framework / Silverlight Two Vulnerabilities MS12-016 (KB2633870, KB2633873, KB2633874, KB2633879, KB2633880, KB2668562)",
	description: "Two vulnerabilities have been reported in Microsoft .NET Framework and\r\nMicrosoft Silverlight, which can be exploited by malicious people to\r\ncompromise a user&#x27;s system.\r\n\r\n1) An unspecified error when handling un-managed objects can be exploited\r\nvia e.g. a specially crafted XAML Browser Application (XBAP).\r\n\r\n2) An error when calculating certain buffer lengths can be exploited to\r\ncorrupt memory via e.g. a specially crafted XAML Browser Application (XBAP).\r\n\r\nSuccessful exploitation of the vulnerabilities allows execution of\r\narbitrary code, but requires a browser that can run a XAML Browser\r\n\r\nApplication (XBAP) or Silverlight application.\r\n\r\nExtended Solution:\r\nAs a workaround disable XAML browser applications in Internet Explorer\r\n(please see the vendor&#x27;s advisory for details).\r\n\r\nVendor note:\r\nThis security update resolves one publicly disclosed vulnerability and one privately reported vulnerability in Microsoft .NET Framework and Microsoft Silverlight. The vulnerabilities could allow remote code execution on a client system if a user views a specially crafted web page using a web browser that can run XAML Browser Applications (XBAPs) or Silverlight applications. Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights\r\n\r\nThis security update is rated Critical for Microsoft .NET Framework 2.0 Service Pack 2, Microsoft .NET Framework 3.5.1, and Microsoft .NET Framework 4 on all supported editions of Microsoft Windows; and for Microsoft Silverlight 4. \r\n\r\nA remote code execution vulnerability exists in Microsoft .NET Framework and Silverlight that can allow a specially crafted Microsoft .NET Framework application to access memory in an unsafe manner. An attacker who successfully exploited this vulnerability could run arbitrary code in the security context of the logged-on user. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights. Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights.\r\n\r\n\r\nSystems affected:\r\nMicrosoft .NET Framework 2.x\r\nMicrosoft .NET Framework 3.x\r\nMicrosoft .NET Framework 4.x\r\nMicrosoft Silverlight 4.x\r\n\r\nNon-Affected Software\r\nSoftware\r\nMicrosoft .NET Framework 1.1 Service Pack 1\r\nMicrosoft .NET Framework 3.5 Service Pack 1\r\nMicrosoft Silverlight 5 when installed on Mac\r\nMicrosoft Silverlight 5 when installed on all releases of Microsoft Windows clients\r\nMicrosoft Silverlight 5 when installed on all releases of Microsoft Windows servers",
	publish_date: "2012-02-14T22:20:33Z",
	cveId: "CVE-2012-0014",
	nveUrl: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-0014"
});

vulnerability_states.push({
	pid: 101,
	cid: 201,
	vid: 1001,
	state: "inProgress"
});
/************* sample data [end] *********************/

/************* helpers [start] *********************/
function adduser(userJson) {
    if (finduserByEmail(userJson.email)) {
        return false;
    }
    users.push(userJson);
    wss.broadcast(JSON.stringify({
        target: 'user',
        type: 'add',
        data: JSON.stringify(userJson)
    }));
    return true;
}

function finduserByEmail(email) {
    for (var index = 0; index < users.length; ++index) {
        var item = users[index];
        if (item.email == email) {
            return item;
        }
    }
    return null;
}

function validateState(state) {
	switch(state.toLowerCase()) {
		case "unhandled": 	return "unhandled";
		case "inprogress": 	return "inProgress";
		case "fixed": 		return "fixed";
		case "wontfix": 	return "wontFix";
	}
	return null;	
}
/************* helpers [end] *********************/

/************* routes [start] *********************/

app.post('/public/register', function(req, res) {
    console.log('/public/register');
    var name = req.body.name;
    var mail = req.body.email;
    var password = req.body.password;
    var userIdentifier = req.body.userIdentifier;
    var newStudent = {
        name: name,
        password: password,
        email: mail,
        userIdentifier: userIdentifier
    };

    res.json(adduser(JSON.parse(JSON.stringify(newStudent))));
});

app.post('/public/login', function(req, res) {
    console.log('/public/login');
    var pwd = req.body.password;
    var mail = req.body.email;

    var item = finduserByEmail(mail);
    if (item != null) {
        if (item.password == pwd) {
            if (!tokens[item.userIdentifier]) {
                var token = createGuid();
                tokens[item.userIdentifier] = {
                    userId: item.userIdentifier,
                    securityToken: token
                };
            }
            res.json(tokens[item.userIdentifier]);
        } else {
            res.json("incorrect password");
        }
    } else {
        res.json("user does not exist");
    }
});

app.post('/users', checkAuth, function(req, res) {
	console.log("/users");
	var userJson = req.body;
    users.push(userJson);
	wss.broadcast(JSON.stringify({
        target: 'user',
        type: 'add',
        data: JSON.stringify(userJson)
    }));
    res.json(true);
});

app.get('/users', checkAuth, function(req, res) {
    res.json(users);
})

app.post('/projects', checkAuth, function(req, res) {
    var projectsJson = req.body;
    projects.push(projectsJson);
    wss.broadcast(JSON.stringify({
        target: 'project',
        type: 'add',
        data: JSON.stringify(projectsJson)
    }));
    res.json(true);
});

app.get('/projects', checkAuth, function(req, res) {
    res.json(projects);
});

app.post('/components', checkAuth, function(req, res) {
    var componentsJson = req.body;
    components.push(componentsJson);
    wss.broadcast(JSON.stringify({
        target: 'component',
        type: 'add',
        data: JSON.stringify(componentsJson)
    }));

    res.json(true);
});

app.get('/components', checkAuth, function(req, res) {
    res.json(components);
});

app.post('/project_components', checkAuth, function(req, res) {
    var p_cJson = req.body;
	project_components.push(p_cJson);
    wss.broadcast(JSON.stringify({
        target: 'project_component',
        type: 'add',
        data: JSON.stringify(p_cJson)
    }));

    res.json(true);
});

app.get('/project_components', checkAuth, function(req, res) {
    res.json(project_components);
});

app.get('/projects/:id/components', checkAuth, function(req, res) {
	var pid = req.params.id;
	var cids = [];
	for(var i = 0; i < project_components.length; i++) {
		if(project_components[i].pid == pid)
			cids.push(project_components[i].cid);
	}
	var data = [];
	for(var i = 0; i < components.length; i++) {
		if(cids.indexOf(components[i].id) >= 0)
			data.push(components[i]);
	}
	res.json(data);
});

app.post('/vulnerabilities', checkAuth, function(req, res) {
    var vulnerabilitiesJson = req.body;
    vulnerabilities.push(vulnerabilitiesJson);
    wss.broadcast(JSON.stringify({
        target: 'vulnerability',
        type: 'add',
        data: JSON.stringify(vulnerabilitiesJson)
    }));
    res.json(true);
});

app.get('/vulnerabilities', checkAuth, function(req, res) {
    res.json(vulnerabilities);
});

app.get('/components/:id/vulnerabilities', checkAuth, function(req, res) {
	var cid = req.params.id;
	var data = [];
	for(var i = 0; i < vulnerabilities.length; i++) {
		if(vulnerabilities[i].cid == cid)
			data.push(vulnerabilities[i]);
	}
	res.json(data);
});

app.get('/vulnerability_states', checkAuth, function(req, res) {
    res.json(vulnerability_states);
});

app.get('/vulnerability_states/projects/:pid/components/:cid/vulnerabilities/:vid', checkAuth, function(req, res) {
	var pid = req.params.pid;
	var cid = req.params.cid;
	var vid = req.params.vid;
	var result = false;
	for(var i = 0; i < vulnerability_states.length; i++) {
		if(pid == vulnerability_states[i].pid &&
				cid == vulnerability_states[i].cid &&
				vid == vulnerability_states[i].vid) 
			result = vulnerability_states[i];
	}
	res.json(result);
});

app.post('/vulnerability_states', checkAuth, function(req, res) {
	var data = req.body;
	var exists = false;
	var result = false;
	if(data != null) {
		for(var i = 0; i < vulnerability_states.length; i++) {
			if(data.pid == vulnerability_states[i].pid &&
					data.cid == vulnerability_states[i].cid &&
					data.vid == vulnerability_states[i].vid) {
				exists = true;
				// update state
				if(validateState(data.state) != null) {
					vulnerability_states[i].state = validateState(data.state);
					wss.broadcast(JSON.stringify({
						target: 'vulnerability_states',
						type: 'update',
						data: JSON.stringify(vulnerability_states[i])
					}));
					result = true;
				} 
				break;
			}
		}
	}
	if(!exists && data != null && data.pid != null 
			&& data.cid != null && data.vid != null 
			&& validateState(data.state) != null) {
		data.state = validateState(data.state);
		vulnerability_states.push(data);
		wss.broadcast(JSON.stringify({
			target: 'vulnerability_states',
			type: 'add',
			data: JSON.stringify(data)
		}));
		result = true;
	}
	res.json(result);
});
/************* routes [end] *********************/