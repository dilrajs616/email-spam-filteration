import requests
import json
import base64

# FastAPI server URL (update if needed)
API_URL = "http://127.0.0.1:8000/analyze-email/"

# Raw email content (example email)
raw_email = """Return-Path: <anuntuldeimobiliare@outlook.com>
Delivered-To: untroubl8492-bruce@untroubled.org
Received: (qmail 565356 invoked from network); 28 Feb 2023 04:02:22 -0000
Received: from EUR05-DB8-obe.outbound.protection.outlook.com (mail-db8eur05olkn2041.outbound.protection.outlook.com [40.92.89.41])
  by vx0.untroubled.org ([45.63.65.23])
  with ESMTP via TCP; 28 Feb 2023 04:02:21 -0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Ms2m9ZsDOhbc0Pktfr4f6SYKgaUhnonpIqbd3sJvmQ7s3PmFT+9oEE5vrbFmLpeKLZzmTobHtorlBx3Gq9zpTNLEXnI75aNhepab3R9HUeHf4UJp19B97pV0b5yFWBF8w8XrJUF2S55N86MCZCacR1hnFYmaUBstuURbXHkuv7JhJqyvqgw8JxcI5++ppJsQmIxYxjkublgnzepTs3zoOBTctqArArS96I5LWz4O10EiNSerSHqVE/L6w4jOjDTUG83WBKxsrf0jTp6yarEV8EQkXEYmLHBJ8+5+lih9yownVWsf2LKUfbjl1pbLVXYmnJTtAc/Dp374aqzCxfVmdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=OXEKNg+GWyVML2Aemk6TB59K1CRmy/LR4r21873gXHs=;
 b=GH/RTYZY4wW8P9YxSJ4cAAW6aP8Bpaali/Nm81K14l3ryJ0YQwIB1boHGKjPWVMWr2zYNlMT6abdT1lOuHzqRpTyTMkEkDLO03Kh/g156x2xLViv+FaI/Kbb6L+1jS+HNKQaO/pIoGm4LuBlLLkzw6pmzSgNfHjlF2Y7OP6qutO3liMGZysdEmIiBiS5RxvLkUreQhazs8bRpSLSmyJEeevNtfRdDSpiCaLxUW6jCKZnY14eX5epGEF+9d5yXR7KhvVya4ydfVtAHJwUxSV6Ii7U+n4Lc+JQJQht7UBDNigpScnAr/1aH15jpPTMmv6LfhMCdre1My1G3JUTg0M0hQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=outlook.com;
 s=selector1;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=OXEKNg+GWyVML2Aemk6TB59K1CRmy/LR4r21873gXHs=;
 b=WdD8HU9DV2ml7ZboatgGBF0k6jnPqjrvgyG2IBywlyDsOFUkt1ZRQPfvkLpYbyLF9iXiBj99VbozGjJiUqlD5Hmkyz9ji17u34DQGOntlBUw2TrIXb7dpuB6K5Pc3VSOO8oyJIrW+Fq7xheB8Ex4+HTUtpBZpGr1Zw04p7l97cTGHl5eQ3xFv2BRCG0kWqIp9060ddnMwGa7ZHQ3p3pb6R3YPQ7LSBs+QB7AOzOX6dBhRm3Y9p2WKvm8Pa5SWywTJhZXuA+6s0eX5LQBdJvkN3jaD33JqGAhyd/d6vX74L+gYV6RUZYgc8Ncf42UZmG8j4xO7ciUzpYclab75Lv+Mg==
Received: from DU0PR10MB5266.EURPRD10.PROD.OUTLOOK.COM (2603:10a6:10:34a::22)
 by PR3PR10MB3819.EURPRD10.PROD.OUTLOOK.COM (2603:10a6:102:4d::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6134.30; Tue, 28 Feb
 2023 04:02:07 +0000
Received: from DU0PR10MB5266.EURPRD10.PROD.OUTLOOK.COM
 ([fe80::d067:93ef:f184:668a]) by DU0PR10MB5266.EURPRD10.PROD.OUTLOOK.COM
 ([fe80::d067:93ef:f184:668a%4]) with mapi id 15.20.6134.025; Tue, 28 Feb 2023
 04:02:07 +0000
From: Anuntul deImobiliare <anuntuldeimobiliare@outlook.com>
Subject: Esti PROPRIETAR de GARSONIERA ?
Thread-Topic: Esti PROPRIETAR de GARSONIERA ?
Thread-Index: AQHZSykjtH8Qt/ythEu5n1UJd5Qvgg==
Date: Tue, 28 Feb 2023 04:02:07 +0000
Message-ID: 
 <DU0PR10MB52667ED9FE59D71F26E5857AB7AC9@DU0PR10MB5266.EURPRD10.PROD.OUTLOOK.COM>
Accept-Language: ro-RO, en-US
Content-Language: ro-RO
X-MS-Has-Attach: yes
X-MS-TNEF-Correlator: 
msip_labels: 
x-tmn: 
 [e/VMFYOxCymuy0Tokwz0fvjVsBWq926v6e1vtIVnWV1xJnW2k4nmnNUUWWPySHhtRCKnBmGhvck=]
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: DU0PR10MB5266:EE_|PR3PR10MB3819:EE_
x-ms-office365-filtering-correlation-id: ff584168-c3fc-4778-a4dd-08db19408f43
x-ms-exchange-slblob-mailprops: 
 Qob1MnwVnppXVz9skk2hr8lKByNjVeB/Z+C/pVajVP6fckQzPPe3LSGfB6RXax84TGRXLJwDQofXtFaTWGT9Nq1RelyCwVkBL1Ph4yZRc94lDx+VAXSeuFHUAHm/hkyPKn5tdMnXrYX1LAZgTceBr4g6lXnwXP14ASqq31DegwsuR6P+r2Iuq4SpOLYS6/Twv1YuP5V7elxnKONmaz4+DNMMaMrq5PA/5rL+nRXnEn8swzuDPwWjtvyy6Ylbo61as9jYgo6i1nbGoF5g/6AeMkdhuHDLJly21Yk246h7VetqlGG7/i8X2RcGTsPsFEEuJAgj3vpx20QjhzA5JfYHOAJ0egyrN7WKipvFcChX15vTrm7iznRyxpXBB0/mMf1KRKu08aH5r8DU3wRWvPJf/qsQMINQRBd2zFwRSSEd6aNKBYWaQj83tJ9grUPAWPoFHcZC5lM775ZFFXr4x3IO+fJiRqVyZuAfyCRqwDu8GUujf7O5jcytp95Lp+HJZp1UOQjvQ/XPbsF7/syokerELMKQQNUheoF1ONarLzIpQLFKSPGe+XIOdKYgjY+L9HB1nTXg5Jkff/de4+mtZDs9nQh8aBgI8InwaE3ngUR+jROo4oJx3SWPyHgDh+2ZPiuzNNz1uT5zyXRYwXeUTjbHsz1IdwpdbHo6SVzvtgrgHLaVZp9pTrdcSrxCWcWCN2HU
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 
 6tHv3AYe99SqgCdQ/vV6mUtb1Dbvk6LiAd3lD5JLcqwjXfnnHsPkMTSUgwf7TWTTDvoEaCOzIjR9j9ikAe8Jhk6xnosGP6fn8q1dcYtoa9iA/LRzC0U8B32rTxP69pO9TxcLvot952WQgzjpc9rZXDR71O+5Dfy52qVQhhzmltazQ3IAIxxkS2fuBR/VJAs/NgdGAj9t9pccJvp5LloD/uczZ16CfZN4Kao4bjIXS1eZgp4WFM17yUCMcCzlTzgGLHjbhLRH/5A38QwmdZl8SihlegoK/2xqk2I/xrAlbgoGXCR7pEpCXff4T5LynLadiTXbAwjLcS/9KBkjsl7ksg==
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: 
 =?iso-8859-2?Q?S9ZMdmxYh/m2u1RHUu5Q9HBYS/G1aINpkkw4szkSmSBtJQpdyA76VEAa4v?=
 =?iso-8859-2?Q?1CK0gFom7dcwhG0OVC1QRqb/kQmF3iUh0ilmQ5JrVPUQoIzlB2bHIcubrV?=
 =?iso-8859-2?Q?9P5ZNaCUNl7xcIlreMJGvLE7WDoP6EN3H6rrMrAse200q5Yg5Xe5kK0Jy3?=
 =?iso-8859-2?Q?jJersIlbqBGsIqgiedW+2TQe/6YMK1tx5Q5VkEvAemaQOqBsOsEyess2Et?=
 =?iso-8859-2?Q?kEe2UrV1jHbSjO8MVZq/c7HF17W94VBeb4u/iS+8peWcPtKtrwB4bmmxOx?=
 =?iso-8859-2?Q?dFWfCgxFzpwh4DLI+CVqXk0siEmAR5nR8GJPNh9EIYi2VUkzosmJy17+0c?=
 =?iso-8859-2?Q?BqCRqdGQbTAybUiTokRsn2TayWPTOd0d5PY7v4TuYxiBiFe4GoG6F1GVuM?=
 =?iso-8859-2?Q?b4nqxEdNCaExqInY+7mAmQdFwfrkaFfUFXuL3t0b6RJ5GNfFDxMfchK+hd?=
 =?iso-8859-2?Q?ZoRvtRU4znTpOQQSo0Ky7zxb/ZbuzqUahf9Ssnm54VytvknC05b4uhwZqN?=
 =?iso-8859-2?Q?Wi20HwAJLWWcsGTsFKT6WJdhbiSu+IB86xlu/zqeH/rXTofI+UvOo0C/Xj?=
 =?iso-8859-2?Q?TXFtUs/Vr151dFXa3RNeA2dygg+Rdv3MTa7WJxa0pYWYXu8OglVX0r8jvg?=
 =?iso-8859-2?Q?Yds4XKK2nj9t6Yh0VbId0KsmvlyuzXi9Tx0+lWb5JhfgP6RnS0+rq1Scdp?=
 =?iso-8859-2?Q?9RBZZy6hzwDw5daURRRl8oYknIXvmJvHPw1LnI+FMBZY4YDeMNfPo2GnJU?=
 =?iso-8859-2?Q?BDPjsZytgbs8nty+Qza9oUr+HATxRsCIlMdBYMz4s6b5a1KGWnDU++9QcE?=
 =?iso-8859-2?Q?zBiuGZmdWUiIMnj35eckoFYoUztFdxBjQOXjT5FxhxJeejhSSm2Ekj0AD2?=
 =?iso-8859-2?Q?NywGIHYF8vo9MAvtnLRagputdiSMVzAYD67rdvHCLmfenyBM247qMY/iNK?=
 =?iso-8859-2?Q?3tr9BsyUtEhsEtxpnBIvw93qtxSmJHeQHGaq5bsthdZ7cF98OA7CXYYb0C?=
 =?iso-8859-2?Q?C45YlF8MS9f6OOFhYbGF+TOagdrVh8iKVOfBe0be4Sdy8WKKga6RGb2v/H?=
 =?iso-8859-2?Q?AZzBi/NqVROjSRKxoiqRWskRHYS0aEabrEkxGMDNcmj3PD+GeKnM4QdotW?=
 =?iso-8859-2?Q?CfSL5G0RuoCF5y8MoZiVU8lnqjsoTaEpNeL96s1V2EKS7DZHb8GnEGItxx?=
 =?iso-8859-2?Q?ebxUMRoaTxzcdMpG6WEGddO5lJKdmVpeqeLP4yYztwhlJUES9O3rxNofK9?=
 =?iso-8859-2?Q?dTThAu3uzbsztaIP8zWj83jAsvkYj3NvgUfK4kRMeHoHGGZnlQbloIweW6?=
 =?iso-8859-2?Q?TVa5uXreUeAWzPYgjTAcuZvREPbVTT8Bxvb6JQIqAxrMPRny2iZrak6xlo?=
 =?iso-8859-2?Q?6ztDH7mBmpTtWAUvP/kndaaH/VFnvJRaTmMIwVUNviSLD8okK6g68=3D?=
Content-Type: multipart/related;
	boundary="_005_DU0PR10MB52667ED9FE59D71F26E5857AB7AC9DU0PR10MB5266EURP_";
	type="multipart/alternative"
MIME-Version: 1.0
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DU0PR10MB5266.EURPRD10.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: ff584168-c3fc-4778-a4dd-08db19408f43
X-MS-Exchange-CrossTenant-originalarrivaltime: 28 Feb 2023 04:02:07.4921
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR3PR10MB3819
--_005_DU0PR10MB52667ED9FE59D71F26E5857AB7AC9DU0PR10MB5266EURP_
Content-Type: multipart/alternative;
	boundary="_000_DU0PR10MB52667ED9FE59D71F26E5857AB7AC9DU0PR10MB5266EURP_"
--_000_DU0PR10MB52667ED9FE59D71F26E5857AB7AC9DU0PR10MB5266EURP_
Content-Type: text/plain; charset="iso-8859-2"
Content-Transfer-Encoding: quoted-printable
[cid:49aa3362-ff26-4594-b106-3a9096df116c][cid:c8957a24-4a03-4eae-be07-7bfe=
680fa3f6]
--_000_DU0PR10MB52667ED9FE59D71F26E5857AB7AC9DU0PR10MB5266EURP_
Content-Type: text/html; charset="iso-8859-2"
Content-Transfer-Encoding: quoted-printable
<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Diso-8859-=
2">
<style type=3D"text/css" style=3D"display:none;"> P {margin-top:0;margin-bo=
ttom:0;} </style>
</head>
<body dir=3D"ltr">
<div style=3D"font-family: Calibri, Arial, Helvetica, sans-serif; font-size=
: 12pt; color: rgb(0, 0, 0); background-color: rgb(255, 255, 255);" class=
=3D"elementToProof">
<img style=3D"max-width: 100%;" class=3D"w-1216 h-338" size=3D"106911" cont=
enttype=3D"image/jpeg" data-outlook-trace=3D"F:1|T:1" src=3D"cid:49aa3362-f=
f26-4594-b106-3a9096df116c"><img style=3D"max-width: 100%;" class=3D"w-960 =
h-480" size=3D"117328" contenttype=3D"image/jpeg" data-outlook-trace=3D"F:1=
|T:1" src=3D"cid:c8957a24-4a03-4eae-be07-7bfe680fa3f6"><br>
</div>
</body>
</html>
--_000_DU0PR10MB52667ED9FE59D71F26E5857AB7AC9DU0PR10MB5266EURP_--
--_005_DU0PR10MB52667ED9FE59D71F26E5857AB7AC9DU0PR10MB5266EURP_
Content-Type: message/external-body; access-type=x-deleted; length=144424
Content-Type: image/jpeg; name="thumbnail_6.jpg"
Content-Description: thumbnail_6.jpg
Content-Disposition: inline; filename="thumbnail_6.jpg"; size=106911;
	creation-date="Tue, 28 Feb 2023 04:00:07 GMT";
	modification-date="Tue, 28 Feb 2023 04:00:07 GMT"
Content-ID: <49aa3362-ff26-4594-b106-3a9096df116c>
Content-Transfer-Encoding: base64
--_005_DU0PR10MB52667ED9FE59D71F26E5857AB7AC9DU0PR10MB5266EURP_
Content-Type: message/external-body; access-type=x-deleted; length=158499
Content-Type: image/jpeg; name="140.jpg"
Content-Description: 140.jpg
Content-Disposition: inline; filename="140.jpg"; size=117328;
	creation-date="Tue, 28 Feb 2023 04:00:09 GMT";
	modification-date="Tue, 28 Feb 2023 04:00:11 GMT"
Content-ID: <c8957a24-4a03-4eae-be07-7bfe680fa3f6>
Content-Transfer-Encoding: base64
--_005_DU0PR10MB52667ED9FE59D71F26E5857AB7AC9DU0PR10MB5266EURP_--

"""

# Option 1: Send raw email directly (escaping handled by json.dumps)
email_data = {
    "raw_email": raw_email
}

# Option 2: Base64 encode the email (safer for large emails)
# email_data["raw_email"] = base64.b64encode(raw_email.encode()).decode()

# Send POST request
headers = {"Content-Type": "application/json"}
response = requests.post(API_URL, headers=headers, data=json.dumps(email_data))

# Print response
print("Response:", response.text)
