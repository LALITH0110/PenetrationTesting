import json
from random import choices

import requests as req
import os

from dotenv import load_dotenv  # New import to load environment variables
from openai import OpenAI
import ast

import tiktoken

#input
responseFormat = {
        "type": "json_schema",
        "json_schema": {
            "name": "Action_Plan",
            "description": "gets the action plan to solve the vulnerability",
            "schema": {
                "type": "object",
                "properties": {
                    # "TotalCost": {
                    #     "type": "string",
                    #     "description": "Total cost of fixing the vulnerability on all systems"
                    # },
                    "CostBreakdown": {
                        "type": "object",
                        "properties": {
                            "costToFix": {
                                "type": "object",
                                "properties": {
                                    "cost":{
                                    "type": "integer",
                                    "description": "The cost (in USD) to fix the vulnerability on a single system.  Do not include labor costs"
                                    },
                                    "Reasoning": {
                                        "type": "string",
                                        "description":"The reason why the cost to fix the vulnerability on a single system is what it is.  Make the response less than 100 characters",
                                    }
                                }
                            },
                            "HardwareCostPerSystem": {
                                "type": "object",
                                "properties": {
                                    "cost":{
                                    "type": "integer",
                                    "description": "If there is a hardware cost to fix the vulnerability (such as replacing computer parts), then this is the cost (in USD) to fix",
                                    },
                                    "Reasoning": {
                                        "type": "string",
                                        "description":" The reason behind the hardware cost.  Make the response less than 100 characters",
                                    }
                                }
                            },

                            # "LaborCostPerSystem": {
                            #     "type": "object",
                            #     "properties": {
                            #         "cost":{
                            #         "type": "integer",
                            #         "description": "The labor cost (in USD) to fix the vulnerability on a single system "
                            #         },
                            #         "Reasoning": {
                            #             "type": "string",
                            #             "description":"The reason why the cost to fix the vulnerability on a single system is what it is",
                            #         }
                            #     }
                            # },
                            # This "Other Costs" schema is gives questionable answers
                            # "Other Costs":{
                            #     "type": "array",
                            #     "items": {
                            #         "type": "object",
                            #         "properties": {
                            #             "costName": {
                            #                 "type": "string",
                            #                 "description": "The name of this expense"
                            #             },
                            #             "cost":{
                            #                 "type": "integer",
                            #                 "description": "The labor cost (in USD) to fix the vulnerability on a single system "
                            #             },
                            #             "reasoning": {
                            #                 "type": "string",
                            #                 "description":"Why the cost exists and breakdown that expense and explain the number",
                            #             },
                            #             "additionalProperties": False,
                            #
                            #         },
                            #         "description": "This is all the extra costs associated with fixing the vulnerability.  Some examples are: network downtime, lost productivity, post-patch testing and monitering, etc.  ",
                            #         "additionalProperties": False,
                            #         "required": [
                            #             "costName", "cost", "reasoning",
                            #         ]
                            #     }
                            # }
                        },
                        "additionalProperties": False,
                        "required": [
                            "costToFix","LaborCostPerSystem",
                        ]

                    },
                    "TimeToFixPerSystemInMinutes":{
                        "type": "integer",
                        "description": "Time, in minutes, to fix the vulnerability on a single computer",
                    },
                    "ActionPlan": {
                        "type": "array",
                        "items":{
                            "type" : "string",
                            "description": "A step in the action plan to fix the vulnerability",
                        },
                        "description": "This an array of steps that are need to fix the vulnerability on all systems.  Use at most 1000 characters"
                    },
                    "SkillsNeeded": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "description": "This is a skill that is needed to fix the vulnerability",
                        },
                        "description": "This is an array of top 3 to 5 skills needed to fix the vulnerability"
                    }

                },
                "additionalProperties": False,
                "required": [
                    "CostBreakdown","TimeToFixPerSystemInMinutes","ActionPlan", "SkillsNeeded"
                ]
            }
        }
    }

def calculate_tokens(text):
    # Calculates the approximate token count for the given text.
    # encoding = tiktoken.encoding_for_model("gpt-4o-2024-08-06")
    encoding = tiktoken.encoding_for_model("gpt-3.5-turbo-1106")
    tokens = encoding.encode(text)
    return len(tokens)

def getCVEPlan(vulnerability, client):

    messages = [
        {"role": "system",
         "content": 'You are a cybersecurity assistant based in the United States.  Your are given information about a vulnerability an you need to find the remaining data. '
         },

        {"role": "user",
         "content": f"find an action plan to solve this vulnerability:\n {vulnerability}"}
    ]

    response = client.beta.chat.completions.parse(
        model="gpt-4o-2024-08-06",  # Use the appropriate model
        messages=messages,
        max_tokens=1500,  # Adjust based on report size
        temperature=0.3,
        response_format=responseFormat
    )
    return ast.literal_eval(response.choices[0].message.content)

def getCVEData(cveID):
    # url to collect data about the CVE
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cveID}"
    # print(f"getting CVE Data from {url}")
    # get data about the CVE ID
    response = req.get(url=url)
    if response.status_code == 404:
        print("CVE not found on nist.gov")
        return ""
    else:
        cveDataRaw = req.get(url=url).json()['vulnerabilities'][0]['cve']
        del cveDataRaw['configurations']
        return cveDataRaw

def getActionPlanFromCVEid(cveID, OpenAIclient):
    # get CVE data from nist.gov
   # cveData = getCVEData(cveID)

    # change to string
    #cveData_str = json.dumps(cveData)

    # calculates token
    #token_count = calculate_tokens(cveData_str)
    # TOKEN_LIMIT = 30000

    actionPlan = None
    # Check if token count is too high
    # if token_count <= TOKEN_LIMIT - 1500 or cveData == "":  # Leave room for response tokens or if there is no CVE data
    #     actionPlan =  getCVEPlan(cveData, OpenAIclient)
    # else:
        # if the token count is too high, then just use the CVE ID in the input.
    actionPlan = getCVEPlan(cveID, OpenAIclient)

    return actionPlan
    #print(str(actionPlan))
    #print(actionPlan["CostBreakdown"])

if __name__ == '__main__':
    # The ID of the CVE
    cveID = "CVE:404595-458490-435003850345"
    # Load environment variables from .env file
    load_dotenv()  # New line to load environment variables

    # Access the API key from the environment variable
    openai_api_key = os.getenv("OPEN_API_KEY")

    # Check if the API key is present
    if not openai_api_key:
        raise ValueError(
            "API Key not found. Ensure that OPENAI_API_KEY is set in the .env file.")  # Error handling if API key is missing

    # Initialize OpenAI client with the API key
    client = OpenAI(api_key=openai_api_key)  # Use the environment variable API key

    actionPlan = getActionPlanFromCVEid(cveID, client)

    # Specify the file name
    filename = cveID.replace("-","_")+"actionPlan.json"
    #print(filename)

    # Save the data as a JSON file
    with open(filename, 'w') as file:
        json.dump(actionPlan, file, indent=4)  # 'indent=4' makes the JSON file more readable

