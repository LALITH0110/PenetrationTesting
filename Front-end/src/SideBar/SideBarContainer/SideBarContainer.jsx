import React from "react";
import "./SideBarContainer.css";
import PreviousChecksContainer from "../PreviousChecksContainer/PreviousChecksContainer";
import TitleContainer from "../TitleContainer/TitleContainer";
import Divider from "@mui/material/Divider";
import ProfileContainer from "../ProfileContainer/ProfileContainer";

export default function SideBarContainer() {
  return (
    <div className="sidebar-container">
      <TitleContainer />
      <Divider sx={{ borderColor: "#E0E7E9" }}></Divider>
      <PreviousChecksContainer />
      <Divider sx={{ borderColor: "#E0E7E9" }}></Divider>
      <ProfileContainer />
    </div>
  );
}
