from twisted.application import service

import gcnhub


## twistd -y service.tac

CONFIG = {
    # Port for TCP server
    'port': 4295,
    # Port for SSL server (if not present, will not run SSL)
    #'sslport': 4296,
    # Path to SSL certificate file
    'certfile': 'service.pem',
    # Path to SSL key file
    'keyfile': 'service.pem'
}

application = service.Application('gCn metahub')

service = gcnhub.make_service(CONFIG)
service.setServiceParent(application)