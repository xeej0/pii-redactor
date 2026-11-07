// CSV writing for downloads. Text starting with = + - @ tab or CR gets a leading ' so Excel/Sheets
// do not run it as a formula (OWASP CSV injection); plain numbers like -500 or 1234.50 are left alone.
export function csvCell(v) {
  let s = v == null ? '' : String(v)
  if (/^[=+\-@\t\r]/.test(s) && !/^[+-]?\d+(\.\d+)?$/.test(s)) s = "'" + s
  return '"' + s.replace(/"/g, '""') + '"'
}
export const toCSV = (rows) => rows.map((r) => r.map(csvCell).join(',')).join('\n')
