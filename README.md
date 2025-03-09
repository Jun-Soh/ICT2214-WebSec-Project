# ICT2214-WebSec-Project

## MyLittlePuny
My Little Pony is a command-line tool that takes in user input, specifically valid ASCII domain names. The tool then generates and outputs a series of domain names, modifying the original input domain with homoglyphs of Unicode characters. The tool will also output the corresponding ASCII domain names of each newly generated domain name and check if the domain has already been registered. Incorporation of AIML will allow for the provision of a similarity/confidence score of generated results compared to the original input, with higher scores indicating little to no visible change in output, resulting in higher success rates in phishing attacks.

My Little Puny aims to automate much of the work needed to generate malicious and legitimate-looking domain names while also providing additional useful information (e.g., is domain registered, similarity to ASCII counterpart). While the tool leans toward offensive security, it can also be used for defensive purposes. Organizations with registered domains can run their domain through the tool and possibly uncover malicious domains that have been registered, masquerading as their domain. This could allow for the blocking of these malicious domains and/or advisory notices against these threats.


## User Manual
1. Install the required Python packages
```sh
kali@kali:~/ICT2214-WebSec-Project# cd Code
kali@kali:~/ICT2214-WebSec-Project/Code# pip3 install -r requirements.txt
```

2. Run the program and provide a domain when asked
```sh
kali@kali:~/ICT2214-WebSec-Project/Code# python3 main.py
Enter target domain to enumerate (e.g. apple.com, google.com): apple.com
```

3. The other scripts will be run automatically, and all their outputs will be saved in output.html.