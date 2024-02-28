# XSShigeno: Automated XSS Detector

Developed by: yaceno  

Website: https://yaceno.github.io/

## Introduction

Detect cross-site scripting vulnerabilities (XSS) with ease using this python tool.

## Prerequisites
- Python Version: Python3
- Required Libraries:
        selenium
        argparse

Install the necessary libraries with:

`pip install -r requirements.txt`

## How to Use

Start with the basic command:

`python3 src/xsshigeno.py -u [URL]`

Available Arguments:
Argument	Description
- -u, --url	[Required] URL of the vulnerable site.
- -p, --parameters	Specify parameters for testing XSS (e.g., "param1,param2,param3"). If not mentioned, the tool will search for parameters.
- -n, --numberpayloads	Number of payloads to inject. Default: 100
- -f, --filepayloads	Specify a file containing payloads. Default: "payloads.txt"
- -m, --numberparams	Number of parameters to search for if -p isn't specified.
- -t, --maxthreads	Set the number of threads (up to 15) to search for parameters and payloads. Default: 1
-   -fi, --detectingfilters        Detect filters by analyzing the response with many payloads sent

For all options and arguments:

`python3 src/xsshigeno.py -h`

## Example 
`python3 src/xsshigeno.py -u https://xss-game.appspot.com/level1/frame -t 10 -n 20`  
This will look for the site mentioned, first searching for parameters and then searching for xss using 10 threads, the default parameters and payloads files and a maximum of 20 payloads to find.

## Future Improvements

    Introduce payload list variations based on specific needs.
    Curate more targeted payload lists.
    Handle XSS in POST parameters.
    Enhance CSP bypass capabilities.
