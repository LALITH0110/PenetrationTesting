import React from "react";
import Avatar from "@mui/material/Avatar";
import "./ProfileContainer.css";

function stringToColor(string) {
  let hash = 0;
  let i;

  for (i = 0; i < string.length; i += 1) {
    hash = string.charCodeAt(i) + ((hash << 5) - hash);
  }

  let color = "#";

  for (i = 0; i < 3; i += 1) {
    const value = (hash >> (i * 8)) & 0xff;
    color += `00${value.toString(16)}`.slice(-2);
  }

  return color;
}

function stringAvatar(name) {
  return {
    sx: {
      bgcolor: stringToColor(name),
      width: 55,
      height: 55,
    },
    children: `${name.split(" ")[0][0]}${name.split(" ")[1][0]}`,
  };
}

export default function ProfileContainer() {
  const today = new Date();
  const date = today.toLocaleDateString();

  return (
    <div className="profile-container">
      <div className="profile-image">
        <Avatar {...stringAvatar("Darshan Nair")} />
      </div>
      <div className="profile-details">
        <div className="profile-name">Darshan S Nair</div>
        <div className="profile-date">{date}</div>
      </div>
    </div>
  );
}
