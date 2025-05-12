def check_spoof(headers):
    from_addr = headers.get('From', '')
    reply_to = headers.get('Reply-To', '')
    return from_addr != reply_to if reply_to else False
