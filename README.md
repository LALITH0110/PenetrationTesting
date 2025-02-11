# PenetrationTesting

This is an advanced machine-learning web exploit framework designed for real-time domain scanning, CVE identification, vulnerability detection, and automated exploitation. This tool also provides actionable security recommendations, including cost analysis and prevention strategies.

## Features
* **Real-time domain scanning:** Scan domains for vulnerabilities across multiple ports and protocols.
* **CVE identification and vulnerability detection:** Identify critical, medium, and low-severity vulnerabilities with detailed CVE references.
* **Automated exploitation:** Exploit detected vulnerabilities for penetration testing purposes.
* **Actionable recommendations for remediation:** Security measures with cost analysis and prevention strategies.
* **Cost analysis and prevention strategies:**
* **Detailed Vulnerability Tables:** Interactive tables displaying service versions, severity levels, and associated CVEs.
* **Interactive Dashboard:**
  * Total vulnerabilities summary.
  * Severity distribution (Critical, Medium, Low).
  * Vulnerabilities per port visualization.
  * Clean ports tracking.

![Uploading Screenshot_2024-10-28_at_1.49.43_PM.png…]() ![Uploading Screenshot_2024-10-28_at_1.49.05_PM.png…]()

## Installation
### Prerequisites
Ensure you have the following installed:
* Python 3
* Flask
* Node.js & npm
* MongoDB (if applicable for data storage)

### Clone the Repository
```
git clone https://github.com/LALITH0110/PenetrationTesting.git
```

## Running the Application
### Step 1: Start the Flask Backend
Open a terminal and run:
```
cd backend
sudo python3 main.py
```
### Step 2: Start the Frontend
In another terminal tab, navigate to the frontend folder and run:
```
cd frontend
npm install  # Install dependencies (first time setup)
npm start  # Start the frontend
```
## Usage
* Enter a target domain for scanning.
* Wait for the output (takes 5-15 min).
* View detailed results in different tabs:
  * Total vulnerabilities detected.
  * Severity breakdown (Critical/Medium/Low).
  * Vulnerabilities by port and protocol.
* Analyze the risk and recommended security measures.
* Use actionable insights to secure the domain.


# Extra resources

## Getting Started with Create React App

This project was bootstrapped with [Create React App](https://github.com/facebook/create-react-app).

## Available Scripts

In the project directory, you can run:

### `npm start`

Runs the app in the development mode.\
Open [http://localhost:3000](http://localhost:3000) to view it in your browser.

The page will reload when you make changes.\
You may also see any lint errors in the console.

### `npm test`

Launches the test runner in the interactive watch mode.\
See the section about [running tests](https://facebook.github.io/create-react-app/docs/running-tests) for more information.

### `npm run build`

Builds the app for production to the `build` folder.\
It correctly bundles React in production mode and optimizes the build for the best performance.

The build is minified and the filenames include the hashes.\
Your app is ready to be deployed!

See the section about [deployment](https://facebook.github.io/create-react-app/docs/deployment) for more information.

### `npm run eject`

**Note: this is a one-way operation. Once you `eject`, you can't go back!**

If you aren't satisfied with the build tool and configuration choices, you can `eject` at any time. This command will remove the single build dependency from your project.

Instead, it will copy all the configuration files and the transitive dependencies (webpack, Babel, ESLint, etc) right into your project so you have full control over them. All of the commands except `eject` will still work, but they will point to the copied scripts so you can tweak them. At this point you're on your own.

You don't have to ever use `eject`. The curated feature set is suitable for small and middle deployments, and you shouldn't feel obligated to use this feature. However we understand that this tool wouldn't be useful if you couldn't customize it when you are ready for it.

## Learn More

You can learn more in the [Create React App documentation](https://facebook.github.io/create-react-app/docs/getting-started).

To learn React, check out the [React documentation](https://reactjs.org/).

### Code Splitting

This section has moved here: [https://facebook.github.io/create-react-app/docs/code-splitting](https://facebook.github.io/create-react-app/docs/code-splitting)

### Analyzing the Bundle Size

This section has moved here: [https://facebook.github.io/create-react-app/docs/analyzing-the-bundle-size](https://facebook.github.io/create-react-app/docs/analyzing-the-bundle-size)

### Making a Progressive Web App

This section has moved here: [https://facebook.github.io/create-react-app/docs/making-a-progressive-web-app](https://facebook.github.io/create-react-app/docs/making-a-progressive-web-app)

### Advanced Configuration

This section has moved here: [https://facebook.github.io/create-react-app/docs/advanced-configuration](https://facebook.github.io/create-react-app/docs/advanced-configuration)

### Deployment

This section has moved here: [https://facebook.github.io/create-react-app/docs/deployment](https://facebook.github.io/create-react-app/docs/deployment)

### `npm run build` fails to minify

This section has moved here: [https://facebook.github.io/create-react-app/docs/troubleshooting#npm-run-build-fails-to-minify](https://facebook.github.io/create-react-app/docs/troubleshooting#npm-run-build-fails-to-minify)
