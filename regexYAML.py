from sys import argv
import re
import yaml

default_rules = ["url:port","url", "password", "apikey", "usr", "base64"]


def define_rules(rule):
    """Define a list of rules to detected

    Args:
        rule (str): string to get regex pattern of string key and value pairs

    Returns:
        str: Pattern regex of string key and value pairs for rule 
    """    
    keyPattern, valuePattern = "", ""
    if rule == "url:port":
        keyPattern = "^.*(Endpoint|host|Host|Registry|hosts|Hosts|HOST|HOSTS).*$"
        valuePattern = "(([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})|(\w*.\w*.\w*)):[0-9]{5}"
    if rule == "url":
        keyPattern = "^.*(Endpoint|host|Host|Registry|hosts|Hosts|HOST|HOSTS).*$"
        valuePattern = "^[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)$"
    if rule == "password":
        keyPattern = "^\S*(pass(words?|wd|phrase)?|pwd|secret|Secret)_?(hash)?[0-9]*$"
        valuePattern = ".*"
    if rule == "apikey":
        keyPattern = "^[A-Za-z0-9\-\_]+(key|token|Key|Token|KEY|TOKEN)$"
        valuePattern = "^(?!.*[ ])"
    if rule == "usr":
        keyPattern = "^.*(Name|name).*$"
        valuePattern = "\w+$"
    if rule == "base64":
        keyPattern = ""
        valuePattern = "^((?!(true|false|True|False|Smtp|warn))[A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"
    return keyPattern, valuePattern


def detect_secrets(lineChecked, location):
    """Detect Secrets from a line of yaml file

    Args:
        lineChecked (string, opt): line of yaml file to check
        location (int, opt): location of secrets to check
    """
    key = ""
    value = ""

    # Detect what the type of string is on YAML files
    count_colon = str(lineChecked).count(":")
    if count_colon == 0:
        value = lineChecked

    if count_colon == 1:
        key = str(lineChecked).split(":")[0]
        value = str(lineChecked).split(":")[1]
        if value.count("#") >= 1:
            index_sharp = value.index("#")
            if '"' in value[index_sharp:]:
                index_quote = str(value[index_sharp:]).index('"')
                value = value[:index_quote]
            else:
                value = value.split("#")[0]
        if value.count("\"") == 2:
            index_quote_first = value.index("\"")
            substr = value[index_quote_first+1:]
            index_quote_second = substr.index("\"")
            value = substr[:index_quote_second]
    if count_colon > 1:
        index_colon = str(lineChecked).index(":")
        key = str(lineChecked)[: index_colon]
        value = str(lineChecked)[index_colon + 1:]
        if value.count("\"") == 2:
            index_quote_first = value.index("\"")
            substr = value[index_quote_first+1:]
            index_quote_second = substr.index("\"")
            value = substr[:index_quote_second]

    # Detect secret values
    secret_check = False
    for rule in default_rules:
        keyPattern = ""
        valuePattern = ""
        keyPattern, valuePattern = define_rules(rule=rule)
        regexKey, regexValue = re.compile(keyPattern), re.compile(valuePattern)
        if secret_check == True:
            break
        if key == "" and regexValue.match(value):
            secret_check = True
            print("Warning the secret is detected by {rule} at {location}".format(rule=rule, location=location))
            continue
        if key != "" and value == "":
            continue
        if key != "" and value != "":
            if rule == "base64" and regexValue.match(value):
                secret_check = True
                print("Warning the secret is detected by {rule} at {location}".format(rule=rule, location=location))
                continue
            elif rule == "password" and regexKey.match(key):
                secret_check = True
                print("Warning the secret is detected by {rule} at {location}".format(rule=rule, location=location))
                continue
            elif regexValue.match(value) and regexKey.match(key):
                secret_check = True
                print("Warning the secret is detected by {rule} at {location}".format(rule=rule, location=location))
                continue
            else:
                continue           

        
    return secret_check


def __main__():
    try:
        try:
            with open(argv[1], "r") as stream:
                count = 1
                for line in stream.readlines():
                    if line.replace(" ", "").startswith("#"):
                        pass
                    elif line == "\n":
                        pass
                    else:
                        detect_secrets(
                            lineChecked=line.replace(" ", "").replace("\n", ""), location=count
                        )
                    count = count + 1
        except FileNotFoundError:
            print("Something wrong on your file, It doesn't exist or wrong path. Try Again !!!")
            exit(1)
    except IndexError:
        print("Missing a path for the log file, pass in and try again !!!")
        exit(1)

if __name__ == "__main__":
    __main__()