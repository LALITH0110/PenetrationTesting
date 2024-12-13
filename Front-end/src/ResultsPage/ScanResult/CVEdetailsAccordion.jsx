import React from "react";
import {
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Typography,
  Box,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";

const CveDetailsAccordion = ({ generalData, data }) => {
  return (
    <Accordion>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography variant="h6" sx={{ marginRight: 2 }}>
          {generalData.CVE}
        </Typography>
        <Typography
          variant="body1"
          sx={{
            fontWeight: "bold",
            color: getSeverityColor(generalData.Severity),
          }}
        >
          Severity: {generalData.Severity}
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        <Box>
          <Typography variant="h6">General Details</Typography>
          <Typography>
            <strong>Port:</strong> {generalData.Port}
          </Typography>
          <Typography>
            <strong>Protocol:</strong> {generalData.Protocol}
          </Typography>
          <Typography>
            <strong>Service:</strong> {generalData.Service}
          </Typography>
          <Typography>
            <strong>Service Version:</strong> {generalData.ServiceVersion}
          </Typography>
          <Typography>
            <strong>Severity:</strong> {generalData.Severity}
          </Typography>
          <a href={data.URL} target="_blank" rel="noopener noreferrer">
            View CVE Details
          </a>
        </Box>

        <Box mt={2}>
          <Typography variant="h6">Cost Breakdown</Typography>
          <Typography>
            <strong>Fix Cost:</strong> ${data.CostBreakdown.costToFix.cost} -{" "}
            {data.CostBreakdown.costToFix.Reasoning}
          </Typography>
          <Typography>
            <strong>Hardware Cost:</strong> $
            {data.CostBreakdown.HardwareCostPerSystem.cost} -{" "}
            {data.CostBreakdown.HardwareCostPerSystem.Reasoning}
          </Typography>
        </Box>

        <Box mt={2}>
          <Typography variant="h6">Time to Fix</Typography>
          <Typography>
            {data.TimeToFixPerSystemInMinutes} minutes per system
          </Typography>
        </Box>

        <Box mt={2}>
          <Typography variant="h6">Action Plan</Typography>
          <ol>
            {data.ActionPlan.map((step, index) => (
              <li key={index}>
                <Typography>{step}</Typography>
              </li>
            ))}
          </ol>
        </Box>

        <Box mt={2}>
          <Typography variant="h6">Skills Needed</Typography>
          <ul>
            {data.SkillsNeeded.map((skill, index) => (
              <li key={index}>
                <Typography>{skill}</Typography>
              </li>
            ))}
          </ul>
        </Box>
      </AccordionDetails>
    </Accordion>
  );
};

// Helper function to return severity color based on value
const getSeverityColor = (severity) => {
  if (severity >= 7.0) return "red"; // High Severity (e.g., CVE score >= 7.0)
  if (severity >= 4.0) return "orange"; // Medium Severity (e.g., CVE score 4.0 - 6.9)
  return "green"; // Low Severity (e.g., CVE score < 4.0)
};

export default CveDetailsAccordion;
