import React from "react";
import { Box, SimpleGrid, Heading } from "@chakra-ui/react";
import BugReportIcon from "@mui/icons-material/BugReport";
import { Grid, GridItem } from "@chakra-ui/react";
import { Pie, Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
} from "chart.js";

import CleaningServicesIcon from "@mui/icons-material/CleaningServices";
import MetricCard from "./Mini-Components/MetricCard";
import PriorityHighIcon from "@mui/icons-material/PriorityHigh";
import WarningIcon from "@mui/icons-material/Warning";
import SafetyCheckIcon from "@mui/icons-material/SafetyCheck";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement
);

const PieChartComponent = ({ pieData }) => {
  return (
    <Box
      sx={{
        width: "400px", // Adjust width as needed
        height: "400px", // Adjust height as needed
        margin: "0 auto", // Center the chart
      }}
    >
      <Pie
        data={pieData}
        options={{
          responsive: true,
          maintainAspectRatio: false, // Allow custom sizing
          plugins: {
            legend: {
              display: true,
              position: "right", // Move the legend to the right side
            },
          },
        }}
      />
    </Box>
  );
};

const BarChartComponent = ({ barData }) => {
  return (
    <Box
      sx={{
        width: "400px", // Adjust width as needed
        height: "400px", // Adjust height as needed
      }}
    >
      <Bar
        data={barData}
        options={{
          responsive: true,
          maintainAspectRatio: false, // Allow custom sizing
          scales: {
            y: {
              beginAtZero: true,
            },
          },
          plugins: {
            legend: {
              display: true,
              position: "bottom", // Move the legend to the bottom
              labels: {
                boxWidth: 20,
                padding: 10,
              },
            },
          },
        }}
      />
    </Box>
  );
};

const VulnOverview = ({ vulnerabilityData, domain }) => {
  const totalVulnerabilities = vulnerabilityData.Ports.reduce(
    (acc, port) => acc + port.Vulnerabilities.length,
    0
  );
  const criticalVulnerabilities = vulnerabilityData.Ports.reduce(
    (acc, port) =>
      acc + port.Vulnerabilities.filter((vuln) => vuln.Severity >= 7).length,
    0
  );
  const mediumVulnerabilities = vulnerabilityData.Ports.reduce(
    (acc, port) =>
      acc +
      port.Vulnerabilities.filter(
        (vuln) => vuln.Severity >= 5 && vuln.Severity < 7
      ).length,
    0
  );
  const lowVulnerabilities =
    totalVulnerabilities - criticalVulnerabilities - mediumVulnerabilities;
  const cleanPorts = vulnerabilityData.Ports.filter(
    (port) => port.Vulnerabilities.length === 0
  ).length;
  const totalPorts = vulnerabilityData.Ports.length;

  const pieData = {
    labels: ["Critical", "Medium", "Low"],
    datasets: [
      {
        data: [
          criticalVulnerabilities,
          mediumVulnerabilities,
          lowVulnerabilities,
        ],
        backgroundColor: ["#FF6D60", "#F7D060", "#98D8AA"],
        hoverBackgroundColor: ["#c53030", "#b7791f", "#2f855a"],
      },
    ],
  };

  const barData = {
    labels: vulnerabilityData.Ports.map((port) => `Port ${port.Port}`),
    datasets: [
      {
        label: "Number of Vulnerabilities",
        data: vulnerabilityData.Ports.map(
          (port) => port.Vulnerabilities.length
        ),
        backgroundColor: "#062c30",
      },
    ],
  };

  return (
    <Box p={4}>
      <Heading sx={{ color: "#062c30" }} mb={10}>
        Network Vulnerability Dashboard : ({domain})
      </Heading>
      <Grid templateColumns="repeat(3, 1fr)" gap={5}>
        <GridItem colSpan={2}>
          <MetricCard
            title="Total Vulnerabilities"
            value={totalVulnerabilities}
            change="Total issues found across all ports"
            color="red"
            customIcon={BugReportIcon}
            maxValue={totalVulnerabilities}
            valueOnly={true}
          />
        </GridItem>
        <GridItem colSpan={1}>
          <MetricCard
            title="Clean Ports"
            value={cleanPorts}
            change={`${((cleanPorts / totalPorts) * 100).toFixed(1)}% of total`}
            color="green"
            customIcon={CleaningServicesIcon}
            maxValue={totalPorts}
            startAngle={0}
            endAngle={360}
            invertedColor={true}
          />
        </GridItem>
        <GridItem colSpan={1}>
          <MetricCard
            title="Critical Vulnerabilities"
            value={criticalVulnerabilities}
            change={`${(
              (criticalVulnerabilities / totalVulnerabilities) *
              100
            ).toFixed(1)}% of total`}
            color="red"
            customIcon={PriorityHighIcon}
            maxValue={totalVulnerabilities}
          />
        </GridItem>
        <GridItem colSpan={1}>
          <MetricCard
            title="Medium Vulnerabilities"
            value={mediumVulnerabilities}
            change={`${(
              (mediumVulnerabilities / totalVulnerabilities) *
              100
            ).toFixed(1)}% of total`}
            color="#F7D060"
            customIcon={WarningIcon}
            maxValue={totalVulnerabilities}
          />
        </GridItem>

        <GridItem colSpan={1}>
          <MetricCard
            title="Low Vulnerability"
            value={lowVulnerabilities}
            change={`${(
              (lowVulnerabilities / totalVulnerabilities) *
              100
            ).toFixed(1)}% of total`}
            color="green"
            customIcon={SafetyCheckIcon}
            maxValue={totalVulnerabilities}
          />
        </GridItem>
      </Grid>
      <Box mt={20}>
        <SimpleGrid columns={[1, 2]} spacing={10}>
          <Box>
            <Heading size="md" mb={4}>
              Vulnerability Severity Distribution
            </Heading>
            <PieChartComponent pieData={pieData} />
          </Box>
          <Box>
            <Heading size="md" mb={4}>
              Vulnerabilities Per Port
            </Heading>
            <BarChartComponent barData={barData} />
          </Box>
        </SimpleGrid>
      </Box>
    </Box>
  );
};

export default VulnOverview;
