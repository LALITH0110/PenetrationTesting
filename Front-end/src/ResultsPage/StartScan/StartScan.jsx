import React from "react";
import "./styles.css";
import TextField from "@mui/material/TextField";
import Box from "@mui/material/Box";
import InputLabel from "@mui/material/InputLabel";
import MenuItem from "@mui/material/MenuItem";
import FormControl from "@mui/material/FormControl";
import Select from "@mui/material/Select";
import Button from "@mui/material/Button";
import SensorOccupiedIcon from "@mui/icons-material/SensorOccupied";
import CircularProgress from "@mui/material/CircularProgress"; // Import CircularProgress
import axios from "axios";

export default function StartScan() {
  const [type, setType] = React.useState("URL");
  const [ipAddress, setIpAddress] = React.useState("");
  const [loading, setLoading] = React.useState(false); // Loading state
  const [scanStarted, setScanStarted] = React.useState(false); // Scan status state

  const handleInputChange = (event) => {
    setIpAddress(event.target.value); // Update state with the input value
  };

  const handleChange = (event) => {
    setType(event.target.value);
  };

  const handleScan = () => {
    console.log(ipAddress);
    const data = {
      ipAddress: ipAddress,
    };
    setLoading(true);

    axios
      .post("http://127.0.0.1:8000/scan", data)
      .then((response) => {
        console.log(response.data);
        setScanStarted(true);
      })
      .catch((error) => {
        console.log(error);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const handleReset = () => {
    setIpAddress("");
    setScanStarted(false);
  };

  return (
    <div className="new-scan-input-container">
      {loading ? (
        <CircularProgress />
      ) : scanStarted ? (
        <div>
          <p>Scan has started! This may take some time.</p>
          <p>You can find it loading in previous scans.</p>
          <Button
            onClick={handleReset}
            variant="contained"
            style={{ backgroundColor: "#062C30" }}
          >
            Start New Scan
          </Button>
        </div>
      ) : (
        <>
          <div className="ip-text-container">
            <TextField
              value={ipAddress}
              onChange={handleInputChange}
              fullWidth
              label="Enter the IP/ Domain Name"
              id="fullWidth"
            />
          </div>
          <Box sx={{ minWidth: 120 }}>
            <FormControl fullWidth>
              <InputLabel id="demo-simple-select-label">Type</InputLabel>
              <Select
                labelId="demo-simple-select-label"
                id="demo-simple-select"
                value={type}
                label="Type"
                onChange={handleChange}
              >
                <MenuItem value={"URL"}>URL</MenuItem>
                <MenuItem value={"IP"}>IP</MenuItem>
              </Select>
            </FormControl>
          </Box>
          <Button
            variant="contained"
            size="large"
            style={{ backgroundColor: "#062C30", height: "50px" }}
            endIcon={<SensorOccupiedIcon />}
            onClick={handleScan}
          >
            Scan
          </Button>
        </>
      )}
    </div>
  );
}
