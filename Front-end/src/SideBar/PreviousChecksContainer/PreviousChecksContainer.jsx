import React from "react";
import "./PreviousChecks.css";
import PreviousCheckElement from "./PreviousCheckElement";
import CreateCheckElement from "./CreateCheckElement";

export default function PreviousChecksContainer() {
  return (
    <div className="prev-checks-container">
      <CreateCheckElement />
      <PreviousCheckElement />
      <PreviousCheckElement />
      <PreviousCheckElement />
      <PreviousCheckElement />
      <PreviousCheckElement />
      <PreviousCheckElement />
      <PreviousCheckElement />
      <PreviousCheckElement />
      <PreviousCheckElement />
    </div>
  );
}
