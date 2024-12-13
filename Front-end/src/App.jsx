import React, { useState } from "react";

import "./styles.css";
// import SideBarContainer from "./SideBar/SideBarContainer/SideBarContainer";

import Typography from "@mui/material/Typography";
import ResultsContainer from "./ResultsPage/ResultsContainer/ResultsContainer";
import { SideBar } from "./CoreUISideBar/SideBar";

function App() {
  var [displayID, setDisplayID] = useState("-1");

  function changeDisplay(id) {
    setDisplayID(id);
  }

  return (
    <>
      <Typography sx={{ fontFamily: "Inter, sans-serif" }}>
        {/* <SideBarContainer /> */}
        <div className="page-cover">
          <SideBar changeDisplay={changeDisplay} />
          <ResultsContainer id={displayID} />
        </div>
      </Typography>
    </>
  );
}

export default App;
