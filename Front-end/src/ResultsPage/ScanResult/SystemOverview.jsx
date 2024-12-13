import React from "react";
import GeneralInfo from "./GeneralInfo";
import PortTable from "./PortTable";

export default function SystemOverview({ data }) {
  return (
    <div className="scan-results-container">
      <GeneralInfo data={data} />
      <PortTable Ports={data.Ports} />
    </div>
  );
}
