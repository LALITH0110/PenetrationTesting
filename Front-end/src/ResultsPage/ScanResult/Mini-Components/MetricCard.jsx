import React from "react";
import { Card, CardContent, Typography, Box } from "@mui/material";
import { Gauge, gaugeClasses } from "@mui/x-charts/Gauge";
import CountUp from "react-countup";

function gaugeColor(value, max) {
  const percentage = (value / max) * 100;
  if (percentage > 70) {
    return "#C62E2E";
  } else if (percentage > 30) {
    return "#FABC3F";
  } else {
    return "#52b202";
  }
}

function invertedGaugeColor(value, max) {
  const percentage = (value / max) * 100;
  if (percentage > 70) {
    return "#52b202";
  } else if (percentage > 30) {
    return "#FABC3F";
  } else {
    return "#C62E2E";
  }
}

const MetricCard = ({
  title,
  value,
  change,
  color,
  customIcon: CustomIcon,
  maxValue,
  startAngle,
  endAngle,
  invertedColor,
  valueOnly,
}) => {
  return (
    <Card
      variant="outlined"
      sx={{
        border: "1px solid #e0e0e0",
        borderRadius: "8px",
        boxShadow: "0 2px 8px rgba(0, 0, 0, 0.1)",
        transition: "transform 0.7s",
        "&:hover": {
          transform: "scale(1.05)",
        },
      }}
    >
      <CardContent>
        <Typography variant="h6" component="div" color="text.secondary">
          {title}
        </Typography>
        {/* <Typography variant="h4" component="div" color="text.primary">
          {value}
        </Typography> */}
        {valueOnly ? (
          <Box
            display="flex"
            justifyContent="center" // Center horizontally
            alignItems="center" // Center vertically
            sx={{ height: 100 }} // Optional: Set a height for spacing
          >
            <Typography variant="h2" component="div" color={"#C62E2E"}>
              <CountUp end={value} duration={2} />
            </Typography>
          </Box>
        ) : (
          <Gauge
            value={value}
            min={0}
            max={100}
            startAngle={startAngle}
            endAngle={endAngle}
            thickness={15}
            valueMax={maxValue}
            sx={{
              height: 100,
              [`& .${gaugeClasses.valueText}`]: {
                fontSize: 20,
                transform: "translate(0px, 0px)",
              },
              [`& .${gaugeClasses.valueArc}`]: {
                fill: invertedColor
                  ? invertedGaugeColor(value, maxValue)
                  : gaugeColor(value, maxValue),
              },
            }}
            text={({ value, valueMax }) => `${value} / ${valueMax}`}
          />
        )}
        <Box
          display="flex"
          alignItems="center"
          justifyContent="flex-end"
          mt={2}
        >
          <CustomIcon sx={{ color: color }} />
          <Typography variant="body2" ml={0.5}>
            {change}
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
};

MetricCard.defaultProps = {
  title: "Default Title",
  value: 0,
  change: "No change",
  color: "black",
  customIcon: null,
  maxValue: 100,
  startAngle: -110,
  endAngle: 110,
  invertedColor: false,
  valueOnly: false,
};

export default MetricCard;
