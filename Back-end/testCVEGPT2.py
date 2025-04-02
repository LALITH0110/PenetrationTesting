
import os
import json

from dotenv import load_dotenv  # New import to load environment variables
from openai import OpenAI

from cveGPT2 import getActionPlanFromCVEid

load_dotenv()  # New line to load environment variables

# Access the API key from the environment variable
openai_api_key = os.getenv("OPEN_API_KEY")

# Check if the API key is present
if not openai_api_key:
    raise ValueError(
        "API Key not found. Ensure that OPENAI_API_KEY is set in the .env file.")

# Initialize OpenAI client with the API key
client = OpenAI(api_key=openai_api_key)  # Use the environment variable API key

if __name__ == '__main__':
    # The ID of the CVE
    cveID = "C94CBDE1-4CC5-5C06-9D18-23CAB216705E"


    print(f"Getting Action plan for cve {cveID}")
    # This method gets action plan from the CVE ID
    actionPlan = getActionPlanFromCVEid(cveID, client)

    # Specify the file name
    filename = cveID.replace("-","_")+"actionPlan.json"

    print(f"saving action plan as {filename}")

    # Save the data as a JSON file
    with open(filename, 'w') as file:
        json.dump(actionPlan, file, indent=4)  # 'indent=4' makes the JSON file more readable

