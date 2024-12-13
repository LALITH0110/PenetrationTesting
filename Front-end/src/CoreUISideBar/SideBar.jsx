import * as React from "react";
import Divider from "@mui/material/Divider";
import "@coreui/coreui/dist/css/coreui.min.css";
import HomeIcon from "@mui/icons-material/Home";
import WifiFindIcon from "@mui/icons-material/WifiFind";
import SafetyCheckIcon from "@mui/icons-material/SafetyCheck";
import Skeleton from "@mui/material/Skeleton";
import axios from "axios";
import {
  CSidebar,
  CSidebarHeader,
  CSidebarNav,
  CNavTitle,
  CNavItem,
  CBadge,
  CNavGroup,
  CSidebarBrand,
} from "@coreui/react";
import "./styles.css";

import logo from "../assets/zebra_ipro_header.png";

export function SideBar({ changeDisplay }) {
  const [scanData, setScanData] = React.useState(null);
  const [error, setError] = React.useState(null);

  React.useEffect(() => {
    const fetchScanStatus = async () => {
      try {
        const response = await axios.get("http://127.0.0.1:8000/scan-status");
        setScanData(response.data);
        console.log(response.data);
      } catch (err) {
        setError(err.message);
      }
    };

    fetchScanStatus();
  }, []);

  return (
    <CSidebar
      className="border-end"
      colorScheme="dark"
      style={{
        height: "100vh",
        position: "fixed",
        backgroundColor: "#062C30",
        color: "#FEFAF6",
        display: "flex",
        flexDirection: "column",
        width: "260px",
      }}
    >
      <CSidebarHeader className="border-bottom">
        <CSidebarBrand className="custom-navbar-brand">
          <img
            src={logo}
            alt="Infiltrate AI Logo"
            style={{ width: "100%", height: "auto" }}
          />
        </CSidebarBrand>
      </CSidebarHeader>
      <CSidebarNav style={{ flex: 1 }}>
        <CNavTitle>Dashboard</CNavTitle>
        <CNavItem href="#">
          <HomeIcon
            style={{
              verticalAlign: "top",
              marginRight: "3px",
              marginBottom: "2px",
            }}
          />{" "}
          Home
        </CNavItem>
        <CNavItem
          onClick={(e) => {
            e.preventDefault();
            changeDisplay("-1");
          }}
          href="#"
        >
          <WifiFindIcon
            style={{
              verticalAlign: "top",
              marginRight: "3px",
              marginBottom: "2px",
            }}
          />
          Start a Scan <CBadge color="primary ms-auto">ADD</CBadge>
        </CNavItem>
        <CNavGroup
          toggler={
            <>
              <SafetyCheckIcon
                style={{
                  verticalAlign: "top",
                  marginRight: "3px",
                  marginBottom: "2px",
                }}
              />{" "}
              Previous Scans
            </>
          }
        >
          {scanData ? (
            <>
              {scanData.map((scan) => (
                <CNavItem
                  onClick={(e) => {
                    e.preventDefault();
                    changeDisplay(scan._id);
                  }}
                  href="#"
                >
                  <span className="nav-icon"></span> {scan.domain}{" "}
                  <CBadge color="primary ms-auto">
                    {scan.Completed ? "COMPLETED" : "ONGONG"}
                  </CBadge>
                </CNavItem>
              ))}
            </>
          ) : (
            <CNavItem onClick={() => {}} href="#">
              <span className="nav-icon"></span>
              <Skeleton variant="text" sx={{ fontSize: "1rem" }} />{" "}
            </CNavItem>
          )}
        </CNavGroup>
        <Divider style={{ borderColor: "whitesmoke" }} />
        <CNavItem href="#" className="nav-item-bottom">
          About Infiltrate AI
        </CNavItem>
        <CNavItem href="#">Profile</CNavItem>
      </CSidebarNav>
    </CSidebar>
  );
}
