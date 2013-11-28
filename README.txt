visemo
======

DMCloud Video Server Monitoring

usage: rtmp_measure.py [-h] [--version] [-s] [-q | -v] -a API_KEY
                       [-d DURATION] [-t TIMEOUT] [-p PASSWORD] [-n NB_USERS]
                       url

positional arguments:
  url                   url of the embedding page

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -s, --store           store intermediate web pages (default False)
  -q, --quiet           run as quiet mode
  -v, --verbose         run as verbose mode
  -a API_KEY, --api-key API_KEY
                        API KEY to retrieve the content
  -d DURATION, --duration DURATION
                        set duration of download in seconds (default 60)
  -t TIMEOUT, --timeout TIMEOUT
                        set duration of timeout for connections (default 10)
  -p PASSWORD, --password PASSWORD
                        Password for the video (if needed)
  -n NB_USERS, --nb_users NB_USERS
                        Number of users to simulate (default 1)
