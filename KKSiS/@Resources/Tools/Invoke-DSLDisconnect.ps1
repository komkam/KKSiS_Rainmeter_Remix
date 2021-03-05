<#
    -------- Fritzbox via TR-064 (uPNP-SOAP) steuern und auslesen ---------------
    ------- inspiriert von @colinardo https://www.administrator.de --------------
#>

# == Parameter ==================================================================
Param(
	[string]$FBIP,
	[string]$USER,
	[string]$PASS
)
# == ENDE Parameter =============================================================


if ($PSVersionTable.PSVersion.Major -lt 3){write-host "ERROR: Minimum Powershell Version 3.0 is required!" -F Yellow; return}

# == Erlaubte TLS Protokolle für die Powershell-Session festlegen
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'

# == XML Service-Beschreibungs XML abrufen und Namespace setzen
[xml]$serviceinfo = Invoke-RestMethod -Method GET -Uri "http://$($FBIP):49000/tr64desc.xml"
[System.Xml.XmlNamespaceManager]$ns = new-Object System.Xml.XmlNamespaceManager $serviceinfo.NameTable
$ns.AddNamespace("ns",$serviceinfo.DocumentElement.NamespaceURI)
# Ignore Certificate Errors
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }


# == Funktion zum senden eines SOAP Requests
function Execute-SOAPRequest {
    param(
        [Xml]$SOAPRequest,
        [string]$soapactionheader,
        [String]$URL
    )
    try{
        $wr = [System.Net.WebRequest]::Create($URL)
        $wr.Headers.Add('SOAPAction',$soapactionheader)
        $wr.ContentType = 'text/xml; charset="utf-8"'
        $wr.Accept      = 'text/xml'
        $wr.Method      = 'POST'
        $wr.PreAuthenticate = $true
        $wr.Credentials = [System.Net.NetworkCredential]::new($USER,$PASS)

        $requestStream = $wr.GetRequestStream()
        $SOAPRequest.Save($requestStream)
        $requestStream.Close()
        [System.Net.HttpWebResponse]$wresp = $wr.GetResponse()
        $responseStream = $wresp.GetResponseStream()
        $responseXML = [Xml]([System.IO.StreamReader]($responseStream)).ReadToEnd()
        $responseStream.Close()
        return $responseXML
    }catch {
        if ($_.Exception.InnerException.Response){
            throw ([System.IO.StreamReader]($_.Exception.InnerException.Response.GetResponseStream())).ReadToEnd()
        }else{
            throw $_.Exception.InnerException
        }
    }
}

function New-Request {
    param(
        [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$urn,
        [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$action,
        [hashtable]$parameter = @{},
        $Protocol = 'https'
    )
        # SOAP Request Body Template
        [xml]$request = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
    </s:Body>
</s:Envelope>
"@
    # Service auslesen
    $service = $serviceinfo.SelectNodes('//ns:service',$ns) | ?{$_.ServiceType -eq $URN}
    if(!$service){throw "URN does not exist."}
    # Action Element erstellen
    $actiontag = $request.CreateElement('u',$action,$service.serviceType)
    # Parameter erstellen
    $parameter.GetEnumerator() | %{
          $el = $request.CreateElement($_.Key)
          $el.InnerText = $_.Value
          $actiontag.AppendChild($el)| out-null
    }
    # Action Element einfügen
    $request.GetElementsByTagName('s:Body')[0].AppendChild($actiontag) | out-null
    # Send request
    $resp = Execute-SOAPRequest $request "$($service.serviceType)#$($action)" "$($Protocol)://$($FBIP):$(@{$true=$script:secport;$false=49000}[($Protocol -eq 'https')])$($service.controlURL)"
    return $resp
}

# Security-Port (https) abfragen
$script:secport = (New-Request -urn "urn:dslforum-org:service:DeviceInfo:1" -action 'GetSecurityPort' -proto 'http').Envelope.Body.GetSecurityPortResponse.NewSecurityPort


# ================================================================================
# == Fritz!Box-Funktion ==========================================================
# ================================================================================


# DSL-Verbindung trennen

function Invoke-DSLDisconnect(){
    $resp = New-Request -urn 'urn:dslforum-org:service:WANPPPConnection:1' -action 'ForceTermination'
    return $resp.Envelope.body
}

Invoke-DSLDisconnect