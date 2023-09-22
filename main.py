# coding: utf8

import typer
import socket
import requests
import validators
import whois
import time
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from geolite2 import geolite2
from typing_extensions import Annotated
from rich.progress import Progress, SpinnerColumn, TextColumn

app = typer.Typer()

def get_flag(country_code):
    _data = {
        'A': '🇦',
        'B': '🇧',
        'C': '🇨',
        'D': '🇩',
        'E': '🇪',
        'F': '🇫',
        'G': '🇬',
        'H': '🇭',
        'I': '🇮',
        'J': '🇯',
        'K': '🇰',
        'L': '🇱',
        'M': '🇲',
        'N': '🇳',
        'O': '🇴',
        'P': '🇵',
        'Q': '🇶',
        'R': '🇷',
        'S': '🇸',
        'T': '🇹',
        'U': '🇺',
        'V': '🇻',
        'W': '🇼',
        'X': '🇽',
        'Y': '🇾',
        'Z': '🇿'
    }
    country_code = country_code.upper()
    return _data[country_code[0]] + _data[country_code[1]]

def format_size(size_bytes):
    size_kb = size_bytes / 1024
    size_mb = size_kb / 1024
    return f"{size_bytes} bytes, {size_kb:.2f} KB, {size_mb:.2f} MB"

@app.command()
def redirect_check(url: Annotated[str, typer.Argument(envvar="REQUESTER_URL")], check_https_redirect: Annotated[bool, typer.Argument(envvar="REQUESTER_CHECK_HTTPS_REDIRECT")] = True, check_www_redirect: Annotated[bool, typer.Argument(envvar="REQUESTER_CHECK_WWW_REDIRECT")] = True, max_timeout: Annotated[int, typer.Argument(envvar="REQUESTER_MAX_TIMEOUT")] = 10, max_redirects: Annotated[int, typer.Argument(envvar="REQUESTER_MAX_REDIRECTS")] = 5, return_ip: Annotated[bool, typer.Argument(envvar="REQUESTER_RETURN_IP")] = True, time_dns_resolution: Annotated[bool, typer.Argument(envvar="REQUESTER_TIME_DNS_RESOLUTION")] = True, return_geoip: Annotated[bool, typer.Argument(envvar="REQUESTER_RETURN_GEOIP")] = True, process_time: Annotated[bool, typer.Argument(envvar="REQUESTER_PROCESS_TIME")] = True, check_whois: Annotated[bool, typer.Argument(envvar="REQUESTER_CHECK_WHOIS")] = True, check_ssl_validity: Annotated[bool, typer.Argument(envvar="REQUESTER_CHECK_HTTPS_VALIDITY")] = True, return_ssl_issuer: Annotated[bool, typer.Argument(envvar="REQUESTER_RETURN_SSL_ISSUER")] = True, return_ssl_expiration: Annotated[bool, typer.Argument(envvar="REQUESTER_RETURN_SSL_EXPIRATION")] = True):
    """
    Test URL for http->https redirection, www->non-www and vice-versa.

    You can also use the REQUESTER_URL and other environment variables.
    """
    # with Progress(
    #     SpinnerColumn(),
    #     TextColumn("[progress.description]{task.description}"),
    #     transient=True,
    # ) as progress:
    #     progress.add_task(description="Processing...", total=None)

    if process_time:
        start_time = time.time()
    if not validators.domain(url.split('//')[-1].split('/')[0]):
        typer.echo(f"❌ The URL {url} is not a Fully Qualified Domain Name (FQDN).")
        return

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    try:
        # Disallow redirects to handle them manually
        r = requests.get(url, allow_redirects=False, timeout=max_timeout)
    except requests.RequestException as e:
        typer.echo(f"❌ Request failed: {e}")
        return

    redirect_count = 0
    while r.is_redirect and redirect_count < max_redirects:
        redirect_count += 1
        try: 
            r = requests.get(r.headers['Location'], allow_redirects=False, timeout=max_timeout)
        except requests.RequestException as e:
            typer.echo(f"Request failed: {e}")
            return

    # At this point, r.url will have the final URL after redirections
    final_url = r.url
    final_fqdn = final_url.split('//')[-1].split('/')[0]

    if check_https_redirect:
        if url.startswith("http://") and final_url.startswith("https://"):
            typer.echo("✅ HTTPS redirect: yes")	
        else:
            typer.echo("❌ HTTPS redirect: no")

    if check_www_redirect:
        www_to_non_www = (
            (url.startswith("http://www.") or url.startswith("https://www."))
            and not (final_url.startswith("http://www.") or final_url.startswith("https://www."))
        )
        non_www_to_www = (
            not (url.startswith("http://www.") or url.startswith("https://www."))
            and (final_url.startswith("http://www.") or final_url.startswith("https://www."))
        )
        
        if www_to_non_www:
            typer.echo("🌐 WWW->NON-WWW redirect: yes")
        else:
            typer.echo("🌐 WWW->NON-WWW redirect: no")
        
        if non_www_to_www:
            typer.echo("🌐 NON-WWW->WWW redirect: yes")
        else:
            typer.echo("🌐 NON-WWW->WWW redirect: no")

    if check_ssl_validity:
        try:
            cert = ssl.get_server_certificate((final_fqdn, 443))
            x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            if x509_cert.not_valid_before < x509_cert.not_valid_after:
                typer.echo("✅ SSL certificate valid: yes")
            else:
                typer.echo("❌ SSL certificate valid: no")
            if return_ssl_expiration:
                typer.echo(f"🔐 SSL expiration date: {x509_cert.not_valid_after}")
        except Exception as e:
            typer.echo(f"[check_ssl_validity]: Error: {str(e)}")

    if return_ssl_issuer:
        try:
            cert = ssl.get_server_certificate((final_fqdn, 443))
            x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            typer.echo(f"🔐 SSL issuer: {x509_cert.issuer.rfc4514_string()}")
        except Exception as e:
            typer.echo(f"Error: {str(e)}")


    typer.echo(f"🕛 Response time: {r.elapsed.total_seconds()} seconds")
    typer.echo(f"📶 HTTP Status code: {r.status_code}")
    typer.echo(f"📦 Page size: {format_size(len(r.content))}")
    if return_ip:
        try:
            # Extract the hostname from the final URL
            hostname = final_url.split('//')[-1].split('/')[0]
            # Capture the time before DNS resolution
            start_time = time.time()
            # Resolve the IP address
            ip_address = socket.gethostbyname(hostname)
            # Capture the time after DNS resolution
            end_time = time.time()
            # Calculate the DNS resolution time
            dns_resolution_time = end_time - start_time
            typer.echo(f"🌐 Server IP: {ip_address}")
            if time_dns_resolution:
                typer.echo(f"🕒 DNS Resolution time: {dns_resolution_time:.7f} seconds")
            if return_geoip:
                reader = geolite2.reader()
                geo_info = reader.get(ip_address)
                geolite2.close()
                if geo_info and 'country' in geo_info:
                    country_code = geo_info['country']['iso_code']
                    country_name = geo_info['country']['names']['en']
                    city_name = geo_info['city']['names']['en'] if 'city' in geo_info and 'names' in geo_info['city'] else 'Unknown city'
                    flag_emoji = get_flag(country_code)
                    typer.echo(f"🌎 Location: {flag_emoji} {country_name}, {city_name}")
                    
                else:
                    typer.echo(f"❌ Could not retrieve geo information: {geo_data['message']}")
            
        except Exception as e:
            typer.echo(f"❌ Could not resolve server IP: {e}")
    
    if check_whois:
        w = whois.whois(final_url.split('//')[-1].split('/')[0])
        # if w.text contains GDPR 
        if 'GDPR' or 'withheldforprivacy' in w.text:
            typer.echo(f"📓 WHOIS: GDPR enabled")
        else:
            org_name = w['org'] if 'org' in w else 'Unknown'
            typer.echo(f"📓 WHOIS information: {org_name}")

    if process_time:
        end_time = time.time()
        total_time = end_time - start_time
        typer.echo(f"🕐 Processed in: {total_time:.7f} seconds")

if __name__ == "__main__":
    app()