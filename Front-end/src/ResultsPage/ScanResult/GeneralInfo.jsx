import React from "react";
import { Card, CardContent, Typography } from "@mui/material";
import ComputerIcon from "@mui/icons-material/Computer";
import MemoryIcon from "@mui/icons-material/Memory";
import ManageHistoryIcon from "@mui/icons-material/ManageHistory";

export default function GeneralInfo({ data }) {
  return (
    <div style={styles.container}>
      {/* Host Card */}
      <Card style={styles.card}>
        <CardContent style={styles.cardContent}>
          <ComputerIcon style={styles.icon} />
          <Typography variant="h5" component="div" style={styles.title}>
            Host
          </Typography>
          <Typography variant="h6" style={styles.content}>
            {data.IP}
          </Typography>
        </CardContent>
      </Card>

      {/* OS Card */}
      <Card style={styles.card}>
        <CardContent style={styles.cardContent}>
          <MemoryIcon style={styles.icon} />
          <Typography variant="h5" component="div" style={styles.title}>
            OS
          </Typography>
          <Typography variant="h6" style={styles.content}>
            {data.OS.Name}
          </Typography>
        </CardContent>
      </Card>

      {/* OS Versions Card */}
      <Card style={styles.card}>
        <CardContent style={styles.cardContent}>
          <ManageHistoryIcon style={styles.icon} />
          <Typography variant="h5" component="div" style={styles.title}>
            OS Versions
          </Typography>
          <Typography variant="h6" style={styles.content}>
            {data.OS.Version}
          </Typography>
        </CardContent>
      </Card>
    </div>
  );
}

const styles = {
  container: {
    display: "flex",
    justifyContent: "space-around",
    marginTop: "20px",
    gap: "80px",
  },
  card: {
    width: "250px",
    backgroundColor: "#062C30",
    boxShadow: "0px 4px 10px rgba(0, 0, 0, 0.2)",
    borderRadius: "8px",
  },
  cardContent: {
    textAlign: "center",
  },
  title: {
    fontWeight: "bold",
    color: "#FFF",
  },
  content: {
    marginTop: "10px",
    color: "#FFF",
  },
  icon: {
    fontSize: "50px",
    color: "#FFF",
  },
};
