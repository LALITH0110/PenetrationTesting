import React from "react";
import "./styles.css";
import StartScan from "../StartScan/StartScan";
import ScanResult from "../ScanResult/ScanResult";

export default function ResultsContainer({ id }) {
  return (
    <div className="results-container">
      {/* <StartScan /> */}
      {id === "-1" ? <StartScan /> : <ScanResult id={id} />}
    </div>
  );
}
