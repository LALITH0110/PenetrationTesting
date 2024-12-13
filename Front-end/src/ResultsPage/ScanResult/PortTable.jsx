import * as React from "react";
import { styled } from "@mui/material/styles";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell, { tableCellClasses } from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Paper from "@mui/material/Paper";

function toRoman(num) {
  const romanMap = [
    { value: 1000, numeral: "M" },
    { value: 900, numeral: "CM" },
    { value: 500, numeral: "D" },
    { value: 400, numeral: "CD" },
    { value: 100, numeral: "C" },
    { value: 90, numeral: "XC" },
    { value: 50, numeral: "L" },
    { value: 40, numeral: "XL" },
    { value: 10, numeral: "X" },
    { value: 9, numeral: "IX" },
    { value: 5, numeral: "V" },
    { value: 4, numeral: "IV" },
    { value: 1, numeral: "I" },
  ];

  let roman = "";

  for (let i = 0; i < romanMap.length; i++) {
    const { value, numeral } = romanMap[i];
    while (num >= value) {
      roman += numeral;
      num -= value;
    }
  }

  return roman;
}

const StyledTableCell = styled(TableCell)(({ theme }) => ({
  [`&.${tableCellClasses.head}`]: {
    backgroundColor: "#062C30",
    color: theme.palette.common.white,
  },
  [`&.${tableCellClasses.body}`]: {
    fontSize: 14,
  },
}));

const StyledTableRow = styled(TableRow)(({ theme }) => ({
  "&:nth-of-type(even)": {
    backgroundColor: "#E4EFE7",
  },
  "&:last-child td, &:last-child th": {
    border: 0,
  },
}));

function createRow(
  list_no,
  port_no,
  protocol,
  state,
  service,
  serviceVersion,
  vulnerabilitiesCount
) {
  return {
    list_no,
    port_no,
    protocol,
    state,
    service,
    serviceVersion,
    vulnerabilitiesCount,
  };
}

function createData(Ports) {
  return Ports.map((port, i) =>
    createRow(
      toRoman(i + 1),
      port.Port,
      port.Protocol,
      port.State,
      port.Service,
      port["Service Version"],
      port.Vulnerabilities.length || 0
    )
  );
}

export default function PortTable({ Ports }) {
  const rows = createData(Ports);

  return (
    <div>
      <h4 className="scan-result-header">Available Ports</h4>
      <TableContainer component={Paper}>
        <Table sx={{ minWidth: 800 }} size="small" aria-label="a dense table">
          <TableHead>
            <TableRow>
              <StyledTableCell>Index</StyledTableCell>
              <StyledTableCell align="center">Port Number</StyledTableCell>
              <StyledTableCell align="center">Protocol</StyledTableCell>
              <StyledTableCell align="center">State</StyledTableCell>
              <StyledTableCell align="left">Service</StyledTableCell>
              <StyledTableCell align="left">Service Version</StyledTableCell>
              <StyledTableCell align="center">
                Vulnerabilities Count
              </StyledTableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((row) => (
              <StyledTableRow key={row.port_no}>
                <StyledTableCell component="th" scope="row">
                  {row.list_no}
                </StyledTableCell>
                <StyledTableCell align="center">{row.port_no}</StyledTableCell>
                <StyledTableCell align="center">{row.protocol}</StyledTableCell>
                <StyledTableCell align="center">{row.state}</StyledTableCell>
                <StyledTableCell align="left">{row.service}</StyledTableCell>
                <StyledTableCell align="left">
                  {row.serviceVersion}
                </StyledTableCell>
                <StyledTableCell align="center">
                  {row.vulnerabilitiesCount}
                </StyledTableCell>
              </StyledTableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  );
}
