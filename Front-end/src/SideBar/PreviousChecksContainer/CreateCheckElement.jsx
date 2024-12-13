import React from "react";
import "./PreviousChecks.css";
import AddCircleOutlineIcon from "@mui/icons-material/AddCircleOutline";

export default function CreateCheckElement() {
  return (
    <>
      <div className="prev-checks-element create-checks-element">
        Start a new check <AddCircleOutlineIcon />
      </div>
    </>
  );
}
