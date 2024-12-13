import * as React from "react";
import "./styles.css";
import SystemOverview from "./SystemOverview";
import VulnOverview from "./VulnOverview";
import PropTypes from "prop-types";
import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Box from "@mui/material/Box";
import VulnerabilityTable from "./VulnerabilityTable";
import axios from "axios";
import CircularProgress from "@mui/material/CircularProgress";

function CustomTabPanel(props) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

CustomTabPanel.propTypes = {
  children: PropTypes.node,
  index: PropTypes.number.isRequired,
  value: PropTypes.number.isRequired,
};

function a11yProps(index) {
  return {
    id: `simple-tab-${index}`,
    "aria-controls": `simple-tabpanel-${index}`,
  };
}

export default function ScanResult(props) {
  const [scanData, setScanData] = React.useState(null);
  const [error, setError] = React.useState(null);
  const [value, setValue] = React.useState(0);

  React.useEffect(() => {
    const fetchScanData = async () => {
      if (!props.id) {
        return;
      }

      try {
        const response = await axios.post("http://127.0.0.1:8000/scan/get", {
          id: props.id,
        });
        setScanData(response.data);
        setError(null);
      } catch (err) {
        setError(err.response?.data?.error || "Error fetching scan data");
        setScanData(null);
      }
    };

    fetchScanData();
  }, [props.id]);

  const handleChange = (event, newValue) => {
    setValue(newValue);
  };

  return (
    <Box sx={{ width: "100%" }}>
      {scanData && scanData.Completed ? (
        <>
          <Box sx={{ borderBottom: 1, borderColor: "divider" }}>
            <Tabs
              value={value}
              onChange={handleChange}
              aria-label="basic tabs example"
            >
              <Tab label="System Overview" {...a11yProps(0)} />
              <Tab label="Vulnerability Overview" {...a11yProps(1)} />
              <Tab label="Vulnerability Table" {...a11yProps(2)} />
            </Tabs>
          </Box>
          <CustomTabPanel value={value} index={0}>
            <SystemOverview data={scanData.ScanData} />
          </CustomTabPanel>
          <CustomTabPanel value={value} index={1}>
            <VulnOverview
              vulnerabilityData={scanData.ScanData}
              domain={scanData.domain}
            />
          </CustomTabPanel>
          <CustomTabPanel value={value} index={2}>
            <VulnerabilityTable vulnerabilities={scanData.ScanData.Ports} />
          </CustomTabPanel>
        </>
      ) : (
        <div
          style={{
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            height: "100vh",
          }}
        >
          {" "}
          <CircularProgress color="secondary" size={100} />
        </div>
      )}
    </Box>
  );
}
