// ===== Imports =====
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import mysql from "mysql2/promise";
import cors from "cors";
import PDFDocument from "pdfkit";
import ExcelJS from "exceljs";

const app = express();

// ===== ENV CONFIG (REQUIRED for Vercel + Hostinger) =====
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret";

// ===== Middleware =====

const allowedOrigins = ["https://bbsfacultyprofile.com"];

// CORS middleware for all requests, including preflight
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET,POST,PUT,DELETE,OPTIONS"
    );
  }

  if (req.method === "OPTIONS") {
    // Preflight request; respond immediately
    return res.status(200).end();
  }

  next();
});

// Parse JSON
app.use(express.json());

// ===== Hostinger MySQL Connection =====
const db = mysql.createPool({
  host: process.env.DB_HOST, // e.g. "mysql.hostinger.com"
  user: process.env.DB_USER, // Hostinger DB user
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME, // faculty_db
  port: 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Wrap top-level await (Vercel-safe)
(async () => {
  try {
    const conn = await db.getConnection();
    console.log("✅ Connected to Hostinger MySQL");
    conn.release();
  } catch (err) {
    console.error("❌ Hostinger DB Connection Error:", err);
  }
})();

// ===== Auth Middlewares =====
export const authenticateToken = (req, res, next) => {
  const token =
    req.cookies.token || req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

export const requireRole = (allowedRoles) => (req, res, next) => {
  if (!req.user || !allowedRoles.includes(req.user.role)) {
    return res.status(403).json({ message: "Access denied" });
  }
  next();
};

// ===== DB Helper Functions =====
export async function getFacultyTables() {
  const [tables] = await db.query(`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name NOT IN ('faculty', 'admin', 'password_resets')
  `);
  return tables.map((t) => t.table_name);
}

export async function getTableColumns(table) {
  const [cols] = await db.query(
    `SELECT column_name FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=?`,
    [table]
  );
  return cols.map((c) => c.column_name);
}

export function normalizeDate(value) {
  if (!value) return null;
  if (value instanceof Date) {
    const yyyy = value.getFullYear();
    const mm = String(value.getMonth() + 1).padStart(2, "0");
    const dd = String(value.getDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
  }
  const parts = value.split("-");
  if (parts.length === 1) return `${parts[0]}-01-01`;
  if (parts.length === 2) return `${parts[0]}-${parts[1]}-01`;
  return value;
}

function formatDateMMYY(value) {
  if (!value) return "N/A";
  const d = new Date(value);
  if (isNaN(d)) return value;
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const year = String(d.getFullYear()).slice(-2);
  return `${month}/${year}`;
}
// ===== Routes =====

// ----- Registration -----
app.post("/api/register", async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password || !role)
      return res
        .status(400)
        .json({ message: "Email, password, and role are required." });

    const [exists] = await db.query("SELECT * FROM faculty WHERE email=?", [
      email,
    ]);
    if (exists.length)
      return res
        .status(400)
        .json({ message: "Faculty with this email already exists." });

    let pin;
    let isUnique = false;
    while (!isUnique) {
      pin = Math.floor(100000 + Math.random() * 900000).toString();
      const [pinCheck] = await db.query("SELECT * FROM faculty WHERE pin=?", [
        pin,
      ]);
      if (!pinCheck.length) isUnique = true;
    }

    await db.query(
      "INSERT INTO faculty (email, password, role, pin) VALUES (?, ?, ?, ?)",
      [email, password, role, pin]
    );

    res.status(201).json({ message: "Registration successful", pin });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ----- Login -----
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password)
      return res
        .status(400)
        .json({ message: "Identifier and password required" });

    // Admin
    const [adminRows] = await db.query("SELECT * FROM admin WHERE email=?", [
      identifier,
    ]);
    if (adminRows.length) {
      const admin = adminRows[0];
      if (admin.password === password) {
        const token = jwt.sign({ pin: "admin", role: "admin" }, JWT_SECRET, {
          expiresIn: "2h",
        });
        res.cookie("token", token, {
          httpOnly: true,
          sameSite: "none",
          secure: true,
        });

        return res.json({ token, role: "admin" });
      } else
        return res.status(401).json({ message: "Invalid admin credentials" });
    }

    // Faculty
    const [facultyRows] = await db.query(
      "SELECT * FROM faculty WHERE email=? OR pin=?",
      [identifier, identifier]
    );
    if (!facultyRows.length)
      return res.status(401).json({ message: "Invalid credentials" });

    const faculty = facultyRows[0];
    if (faculty.password !== password)
      return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { pin: faculty.pin, role: faculty.role },
      JWT_SECRET,
      { expiresIn: "2h" }
    );
    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "none",
      secure: true,
    });

    res.json({ token, role: faculty.role });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ----- Logout -----
app.post("/api/logout", (req, res) => {
  res.clearCookie("token", { httpOnly: true, sameSite: "lax" });
  res.json({ message: "Logged out successfully" });
});

// ===== Dynamic CRUD for all tables (admin/faculty) =====
const registerFacultyRoutes = async () => {
  const tables = await getFacultyTables();

  tables.forEach((table) => {
    // READ
    app.get(`/api/${table}`, authenticateToken, async (req, res) => {
      try {
        let query = `SELECT * FROM \`${table}\``;
        const params = [];
        if (req.user.role === "faculty") {
          query += " WHERE pin=?";
          params.push(req.user.pin);
        } else if (req.user.role === "admin" && req.query.pin) {
          query += " WHERE pin=?";
          params.push(req.query.pin);
        }
        const [rows] = await db.query(query, params);
        res.json(rows);
      } catch (err) {
        console.error(`Error fetching ${table}:`, err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // CREATE
    app.post(
      `/api/${table}`,
      authenticateToken,
      requireRole(["faculty", "admin"]),
      async (req, res) => {
        try {
          const data = req.body || {};
          const pin = req.user.role === "faculty" ? req.user.pin : data.pin;
          if (!pin)
            return res.status(400).json({ message: "PIN is required." });

          const columns = await getTableColumns(table);

          // ===== Normalize DATE/YEAR columns =====
          for (const key of Object.keys(data)) {
            if (columns.includes(key)) {
              const [[colInfo]] = await db.query(
                `SELECT DATA_TYPE FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=?`,
                [table, key]
              );
              if (
                colInfo?.DATA_TYPE === "date" ||
                colInfo?.DATA_TYPE === "year"
              ) {
                data[key] = normalizeDate(data[key]);
              }
            }
          }

          const dataKeys = Object.keys(data).filter((k) => k !== "pin");
          const cols = dataKeys.map((k) => `\`${k}\``).join(","); // escape column names
          const vals = dataKeys.map((k) => data[k]);
          const placeholders = ["?", ...dataKeys.map(() => "?")].join(",");
          const sql = cols
            ? `INSERT INTO \`${table}\` (pin, ${cols}) VALUES (${placeholders})`
            : `INSERT INTO \`${table}\` (pin) VALUES (?)`;
          const params = cols ? [pin, ...vals] : [pin];

          await db.query(sql, params);
          res.status(201).json({ message: `${table} entry added` });
        } catch (err) {
          console.error(`Insert error in ${table}:`, err);
          res.status(500).json({ message: "Server error" });
        }
      }
    );

    // UPDATE
    app.put(
      `/api/${table}/:id`,
      authenticateToken,
      requireRole(["faculty", "admin"]),
      async (req, res) => {
        try {
          const { id } = req.params;
          const data = req.body || {};
          const dataKeys = Object.keys(data);
          if (!dataKeys.length)
            return res.status(400).json({ message: "No fields to update." });

          const columns = await getTableColumns(table);
          for (const key of dataKeys) {
            if (columns.includes(key)) {
              const [[colInfo]] = await db.query(
                `SELECT DATA_TYPE FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=?`,
                [table, key]
              );
              if (
                colInfo?.DATA_TYPE === "date" ||
                colInfo?.DATA_TYPE === "year"
              ) {
                data[key] = normalizeDate(data[key]);
              }
            }
          }

          const sets = dataKeys.map((c) => `${c}=?`).join(",");
          const vals = dataKeys.map((k) => data[k]);
          let query = `UPDATE \`${table}\` SET ${sets} WHERE id=?`;
          const params = [...vals, id];
          if (req.user.role === "faculty") {
            query += " AND pin=?";
            params.push(req.user.pin);
          }

          const [result] = await db.query(query, params);
          if (!result.affectedRows)
            return res.status(404).json({ message: "Record not found" });
          res.json({ message: `${table} updated` });
        } catch (err) {
          console.error(`Update error in ${table}:`, err);
          res.status(500).json({ message: "Server error" });
        }
      }
    );

    // DELETE
    app.delete(
      `/api/${table}/:id`,
      authenticateToken,
      requireRole(["faculty", "admin"]),
      async (req, res) => {
        try {
          const { id } = req.params;
          let query = `DELETE FROM \`${table}\` WHERE id=?`;
          const params = [id];
          if (req.user.role === "faculty") {
            query += " AND pin=?";
            params.push(req.user.pin);
          }
          const [result] = await db.query(query, params);
          if (!result.affectedRows)
            return res.status(404).json({ message: "Record not found" });
          res.json({ message: `${table} deleted` });
        } catch (err) {
          console.error(`Delete error in ${table}:`, err);
          res.status(500).json({ message: "Server error" });
        }
      }
    );
  });
};

// Initialize dynamic faculty routes
registerFacultyRoutes();

// ----- Excel Export -----
app.get(
  "/api/faculty/download-csv",
  authenticateToken,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const tables = await getFacultyTables();
      const workbook = new ExcelJS.Workbook();

      // Fetch all faculty basic info
      const [facultyRows] = await db.query(`
        SELECT f.pin, p.name, f.email
        FROM faculty f
        LEFT JOIN personal_information p ON f.pin = p.pin
      `);

      if (!facultyRows.length)
        return res.status(404).json({ message: "No faculty found" });

      // Table headings mapping
      const tableHeadings = {
        personal_information: [
          "Pin",
          "Name",
          "Specialty",
          "Faculty School",
          "Academic Rank",
          "Email",
        ],
        education: [
          "Pin",
          "Year",
          "Degree",
          "Specialization",
          "Institution",
          "Country",
        ],
        academic_administrative_role: [
          "Pin",
          "Starting Date",
          "Ending Date",
          "Position",
          "Institution",
          "Country",
        ],
        academic_experience: [
          "Pin",
          "Starting Date",
          "Ending Date",
          "Academic Rank",
          "Institution",
          "Nature of Experience",
          "Country",
        ],
        academic_journal_articles: [
          "Pin",
          "Year",
          "Title",
          "Journal Name",
          "DOI Link",
          "Quartile",
          "ABDC",
          "ABS",
          "WOS JIF",
        ],
        awards: ["Pin", "Year", "Award Type", "Award Name", "Institution"],
        book: ["Pin", "Year", "Book Title", "Publisher", "Country"],
        book_chapters: [
          "Pin",
          "Year",
          "Chapter Title",
          "Book Title",
          "Publisher",
          "Country",
        ],
        case_publications: [
          "Pin",
          "Year",
          "Title",
          "Publisher",
          "Journal Type",
          "Used for Classroom Teaching",
          "Country",
        ],
        committee_service: [
          "Pin",
          "Year",
          "Committee Name",
          "Institution",
          "Committee Role",
          "Country",
        ],
        academic_event_organized: [
          "Pin",
          "Year",
          "Event Type",
          "Name",
          "Title",
          "Institution",
          "Role",
          "Country",
        ],
        conference_proceeding: [
          "Pin",
          "Conference Date",
          "Paper Title",
          "Conference Title",
          "Organizer Name",
          "Country",
          "Scopus Indexed",
        ],
        conference_session_chair: [
          "Pin",
          "Year",
          "Presentations",
          "Conference Title",
          "Organizer Name",
          "Country",
        ],
        editorial_service: [
          "Pin",
          "Year From",
          "Year Upto",
          "Name",
          "Category",
          "Editorial Role",
          "Scopus",
          "Country",
        ],
        event_workshop: [
          "Pin",
          "Year",
          "Title",
          "Significant Participation",
          "Country",
        ],
        industry_experience: [
          "Starting Date",
          "Ending Date",
          "Position",
          "Institution",
          "Nature of Experience",
          "Country",
        ],
        industry_report: [
          "Pin",
          "Year",
          "Title",
          "Organization Name",
          "Industry Name",
          "Country",
        ],
        intellectual_contributions: [
          "Pin",
          "Year",
          "Basic Scholarship Number",
          "Applied Scholarship Number",
          "Teaching Learning Scholarship Number",
        ],
        op_ed: ["Title", "Newspaper Name", "Year", "Country"],
        organizational_membership: [
          "Pin",
          "Starting Date",
          "Ending Date",
          "Position",
          "Association",
          "Country",
        ],
        professional_certification: [
          "Pin",
          "Awarding Year",
          "Certification",
          "Certification Association",
        ],
        research_grant: [
          "Pin",
          "Year",
          "Title",
          "Grant Number",
          "Institution",
          "Amount",
          "Country",
        ],
        research_grant_proposal_reviewed: [
          "Pin",
          "Year",
          "Title",
          "Grant Number",
          "Institution",
          "Amount",
          "Country",
        ],
        research_profile: [
          "Pin",
          "Scopus Profile",
          "No of Citation",
          "H Index",
          "ORCID ID",
          "Google Scholar",
        ],
        research_supervision: [
          "Pin",
          "Year",
          "Thesis Title",
          "Research Role",
          "Degree",
          "Institution",
          "Country",
        ],
        review_activity: ["Pin", "Year", "No of Articles", "Journal Name"],
        social_service: [
          "Pin",
          "Year",
          "Institution",
          "Social Service Role",
          "Country",
        ],
        teaching_cases: [
          "Pin",
          "Year",
          "Title",
          "Case Journal Name",
          "Publication Type",
          "Used in Classroom",
          "Publisher",
          "DOI",
        ],
        text_book: [
          "Pin",
          "Year",
          "Type",
          "Title",
          "Publication",
          "Discipline",
          "Country",
        ],
        trade_journal: [
          "Pin",
          "Year",
          "Title",
          "Journal Name",
          "DOI",
          "Publisher",
          "Country",
        ],
        new_program_development: [
          "Pin",
          "Year",
          "Program Name",
          "Role",
          "Program Level",
        ],
        new_degree_course_development: [
          "Pin",
          "Year",
          "Course Name",
          "Course Level",
          "Role",
          "Nature",
        ],
        professional_certificate_development: [
          "Pin",
          "Year",
          "Certificate Name",
          "Certificate Level",
          "Role",
          "Nature",
        ],
        consultation_services: [
          "Pin",
          "Starting Date",
          "Ending Date",
          "Role",
          "Name of Client",
          "Industry",
          "Country",
        ],
        business_ownership: [
          "Pin",
          "Starting Date",
          "Ending Date",
          "Role",
          "Business Name",
          "Industry",
          "Country",
        ],
        brand_membership: [
          "Pin",
          "Starting Date",
          "Ending Date",
          "Role",
          "Brand Name",
          "Industry",
          "Country",
        ],
        contribution_to_media: [
          "Pin",
          "Year",
          "Media Name",
          "Topic Discussed",
          "Represented BracU?",
        ],
        certificate_course_development: [
          "Pin",
          "Year",
          "Certificate Name",
          "Certificate Level",
          "Role",
          "Nature",
        ],
        speech_delivered: [
          "Pin",
          "Year",
          "Type of Speaker",
          "Organization Name",
          "Industry",
          "Title",
          "Country",
        ],
        training_delivered: [
          "Pin",
          "Starting Date",
          "Ending Date",
          "Title",
          "Organization",
          "Industry",
          "Country",
        ],
      };

      for (const table of tables) {
        const sheet = workbook.addWorksheet(
          table.replace(/_/g, " ").toUpperCase()
        );

        // Determine headings for this table
        const headings = tableHeadings[table] || ["Pin"];
        sheet.addRow(headings); // Add header row

        // Fetch each faculty's data for this table
        for (const faculty of facultyRows) {
          const [rows] = await db.query(
            `SELECT * FROM \`${table}\` WHERE pin=?`,
            [faculty.pin]
          );

          if (rows.length) {
            rows.forEach((r) => {
              const actualCols = Object.keys(r).filter(
                (c) => c !== "id" && c !== "pin"
              );

              const rowData = [faculty.pin];
              headings.slice(1).forEach((header) => {
                // Match heading to column (ignore case & underscores)
                const matchedCol = actualCols.find(
                  (col) =>
                    col.toLowerCase().replace(/_/g, "") ===
                    header.toLowerCase().replace(/ /g, "")
                );
                rowData.push(matchedCol ? r[matchedCol] ?? "N/A" : "N/A");
              });

              sheet.addRow(rowData);
            });
          } else {
            // No data for this faculty
            sheet.addRow([
              faculty.pin,
              ...Array(headings.length - 1).fill("N/A"),
            ]);
          }
        }

        // Style header row
        const headerRow = sheet.getRow(1);
        headerRow.eachCell((cell) => {
          cell.font = { bold: true, color: { argb: "FFFFFFFF" } };
          cell.fill = {
            type: "pattern",
            pattern: "solid",
            fgColor: { argb: "FF1E3A8A" },
          };
          cell.alignment = { vertical: "middle", horizontal: "center" };
        });

        // Freeze top row
        sheet.views = [{ state: "frozen", ySplit: 1 }];

        // Adjust column widths safely
        sheet.columns.forEach((col, idx) => {
          let maxLength = 15;
          sheet.eachRow((row) => {
            const cellValue = row.getCell(idx + 1).value;
            if (cellValue)
              maxLength = Math.max(maxLength, String(cellValue).length + 5);
          });
          col.width = maxLength;
        });

        // Auto-filter
        sheet.autoFilter = {
          from: "A1",
          to: `${String.fromCharCode(65 + sheet.columns.length - 1)}1`,
        };
      }

      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      );
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="faculty_full_data.xlsx"`
      );

      await workbook.xlsx.write(res);
      res.end();
    } catch (err) {
      console.error("Excel download error:", err);
      res.status(500).json({ message: "Server error while generating Excel" });
    }
  }
);

// ===== Dynamic CV Download for self =====
app.get("/api/download-cv", authenticateToken, async (req, res) => {
  try {
    const facultyPin = req.user.pin;
    if (!facultyPin)
      return res.status(400).json({ message: "PIN missing from token." });

    const doc = new PDFDocument({ size: "A4", margin: 50 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="faculty_cv_${facultyPin}.pdf"`
    );
    doc.pipe(res);

    const tables = await getFacultyTables();

    let personal = {};
    if (tables.includes("personal_information")) {
      const [rows] = await db.query(
        `SELECT * FROM personal_information WHERE pin=?`,
        [facultyPin]
      );
      personal = rows[0] || {};
    }

    doc
      .font("Helvetica-Bold")
      .fontSize(20)
      .fillColor("#1e3a8a")
      .text(personal.name || "Faculty Member", { align: "center" });
    doc
      .font("Helvetica")
      .fontSize(12)
      .fillColor("gray")
      .text(personal.email || "", { align: "center" });
    doc.moveDown(1);
    drawSectionTitle(doc, "Personal Information");
    drawKeyValueTable(doc, [
      ["PIN", personal.pin || "N/A"],
      ["Name", personal.name || "N/A"],
      ["Specialty", personal.specialty || "N/A"],
      ["Faculty School", personal.faculty_school || "N/A"],
      ["Academic Rank", personal.academic_rank || "N/A"],
      ["Email", personal.email || "N/A"],
    ]);

    for (const table of tables) {
      if (table === "personal_information") continue;
      const columns = await getTableColumns(table);
      const [rows] = await db.query(`SELECT * FROM \`${table}\` WHERE pin=?`, [
        facultyPin,
      ]);
      const dataRows = rows.length
        ? rows.map((r) => columns.map((c) => r[c] ?? "N/A"))
        : [columns.map(() => "N/A")];
      const filteredColumns = columns.filter((c) => c !== "id" && c !== "pin");

      const filteredRows = dataRows.map((r) =>
        r
          .filter((_, idx) => filteredColumns.includes(columns[idx]))
          .map((cell, idx) => {
            const colName = filteredColumns[idx].toLowerCase();
            if (colName.includes("year") || colName.includes("date")) {
              return formatDateMMYY(cell);
            }
            return cell;
          })
      );

      drawSectionTitle(
        doc,
        table.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())
      );
      drawTable(doc, filteredRows, filteredColumns);
      doc.moveDown(0.5);
    }

    doc.end();
  } catch (err) {
    console.error("CV generation error:", err);
    if (!res.headersSent)
      res.status(500).json({ message: "Error generating CV" });
  }
});

// ===== Admin CV Download for any faculty =====
app.get(
  "/api/admin/faculty/:pin/download-cv",
  authenticateToken,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const facultyPin = req.params.pin;
      if (!facultyPin)
        return res.status(400).json({ message: "PIN is required" });

      const doc = new PDFDocument({ size: "A4", margin: 50 });
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="faculty_cv_${facultyPin}.pdf"`
      );
      doc.pipe(res);

      const tables = await getFacultyTables();

      let personal = {};
      if (tables.includes("personal_information")) {
        const [rows] = await db.query(
          `SELECT * FROM personal_information WHERE pin=?`,
          [facultyPin]
        );
        personal = rows[0] || {};
      }

      doc
        .font("Helvetica-Bold")
        .fontSize(20)
        .fillColor("#1e3a8a")
        .text(personal.name || "Faculty Member", { align: "center" });
      doc
        .font("Helvetica")
        .fontSize(12)
        .fillColor("gray")
        .text(personal.email || "", { align: "center" });
      doc.moveDown(1);
      drawSectionTitle(doc, "Personal Information");
      drawKeyValueTable(doc, [
        ["PIN", personal.pin || "N/A"],
        ["Name", personal.name || "N/A"],
        ["Specialty", personal.specialty || "N/A"],
        ["Faculty School", personal.faculty_school || "N/A"],
        ["Academic Rank", personal.academic_rank || "N/A"],
        ["Email", personal.email || "N/A"],
      ]);

      for (const table of tables) {
        if (table === "personal_information") continue;
        const columns = await getTableColumns(table);
        const [rows] = await db.query(
          `SELECT * FROM \`${table}\` WHERE pin=?`,
          [facultyPin]
        );
        const dataRows = rows.length
          ? rows.map((r) => columns.map((c) => r[c] ?? "N/A"))
          : [columns.map(() => "N/A")];
        const filteredColumns = columns.filter(
          (c) => c !== "id" && c !== "pin"
        );

        const filteredRows = dataRows.map((r) =>
          r
            .filter((_, idx) => filteredColumns.includes(columns[idx]))
            .map((cell, idx) => {
              const colName = filteredColumns[idx].toLowerCase();
              if (colName.includes("year") || colName.includes("date")) {
                return formatDateMMYY(cell);
              }
              return cell;
            })
        );

        drawSectionTitle(
          doc,
          table.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())
        );
        drawTable(doc, filteredRows, filteredColumns);
        doc.moveDown(0.5);
      }

      doc.end();
    } catch (err) {
      console.error("Admin CV generation error:", err);
      if (!res.headersSent)
        res.status(500).json({ message: "Error generating CV" });
    }
  }
);

// ===== Password reset endpoints =====
app.post("/api/forgot-password/check", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required." });

    const [reset] = await db.query(
      "SELECT token FROM password_resets WHERE email=? AND expires>NOW()",
      [email]
    );
    if (!reset.length)
      return res.json({
        token: null,
        message: "No valid token exists. Contact admin.",
      });

    res.json({ token: reset[0].token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/reset-password/validate/:token", async (req, res) => {
  try {
    const { token } = req.params;
    if (!token) return res.json({ valid: false });

    const [resetData] = await db.query(
      "SELECT email, expires FROM password_resets WHERE token=?",
      [token]
    );
    if (!resetData.length) return res.json({ valid: false });

    if (new Date(resetData[0].expires) < new Date()) {
      await db.query("DELETE FROM password_resets WHERE token=?", [token]);
      return res.json({ valid: false });
    }

    res.json({ valid: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ valid: false });
  }
});

app.post("/api/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { newPassword } = req.body;
    if (!newPassword)
      return res.status(400).json({ message: "New password is required." });

    const [resetData] = await db.query(
      "SELECT email, expires FROM password_resets WHERE token=?",
      [token]
    );
    if (!resetData.length)
      return res.status(400).json({ message: "Invalid or expired token." });

    if (new Date(resetData[0].expires) < new Date()) {
      await db.query("DELETE FROM password_resets WHERE token=?", [token]);
      return res.status(400).json({ message: "Token expired." });
    }

    const email = resetData[0].email;
    await db.query("UPDATE faculty SET password=? WHERE email=?", [
      newPassword,
      email,
    ]);
    await db.query("DELETE FROM password_resets WHERE token=?", [token]);
    res.json({ message: "Password reset successfully." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ===== PDF Helper functions =====
function drawSectionTitle(doc, title) {
  const spaceNeeded = 60;
  if (doc.y + spaceNeeded > doc.page.height - doc.page.margins.bottom)
    doc.addPage();
  doc.moveDown(0.5);
  doc
    .font("Helvetica-Bold")
    .fontSize(14)
    .fillColor("#1e3a8a")
    .text(title, 50, doc.y, { width: 500, align: "left" });
  const lineY = doc.y + 6;
  doc
    .strokeColor("#1e3a8a")
    .lineWidth(1)
    .moveTo(50, lineY)
    .lineTo(550, lineY)
    .stroke();
  doc.moveDown(0.8);
}
function drawKeyValueTable(doc, rows) {
  const startX = 50,
    tableWidth = 500,
    keyWidth = 150,
    valueWidth = tableWidth - keyWidth,
    padding = 6;
  const bottomMargin = doc.page.margins.bottom;
  let y = doc.y;
  for (const [key, value] of rows) {
    const rowHeight =
      Math.max(
        doc.heightOfString(String(key), { width: keyWidth - padding * 2 }),
        doc.heightOfString(String(value), { width: valueWidth - padding * 2 })
      ) + 10;
    if (y + rowHeight > doc.page.height - bottomMargin) {
      doc.addPage();
      y = doc.page.margins.top;
    }
    doc
      .rect(startX, y, tableWidth, rowHeight)
      .fill("#ffffff")
      .stroke("#e6e6e6");
    doc
      .font("Helvetica-Bold")
      .fontSize(9)
      .fillColor("#1e3a8a")
      .text(String(key), startX + padding, y + 5, {
        width: keyWidth - padding * 2,
      });
    doc
      .font("Helvetica")
      .fontSize(9)
      .fillColor("black")
      .text(String(value), startX + keyWidth + padding, y + 5, {
        width: valueWidth - padding * 2,
      });
    y += rowHeight;
  }
  doc.y = y + 8;
}
function drawTable(doc, rows, headers) {
  const startX = 50;
  const tableWidth = 500;
  const colCount = headers.length;
  const colWidth = tableWidth / colCount;
  const padding = 5;
  const minHeaderHeight = 22;
  const bottomMargin = doc.page.margins.bottom;
  const pageTop = doc.page.margins.top;

  let y = doc.y;

  const drawHeader = () => {
    let headerHeight = minHeaderHeight;

    for (let i = 0; i < colCount; i++) {
      const x = startX + i * colWidth;
      const headerText = headers[i];

      // Fit header text: reduce font size if too long
      let fontSize = 10;
      doc.font("Helvetica-Bold").fontSize(fontSize);
      while (
        doc.widthOfString(headerText) > colWidth - 2 * padding &&
        fontSize > 6
      ) {
        fontSize -= 0.5;
        doc.fontSize(fontSize);
      }

      // Draw cell background
      doc.rect(x, y, colWidth, headerHeight).fill("#1e3a8a");

      // Draw text centered
      doc
        .fillColor("white")
        .text(headerText, x + padding, y + (headerHeight - fontSize) / 2 - 1, {
          width: colWidth - 2 * padding,
          align: "center",
        });

      // Draw cell border
      doc.rect(x, y, colWidth, headerHeight).stroke("#000000");
    }
    y += headerHeight;
  };

  if (y + minHeaderHeight + 30 > doc.page.height - bottomMargin) {
    doc.addPage();
    y = pageTop;
  }

  drawHeader();

  doc.font("Helvetica").fontSize(9);

  rows.forEach((row, rowIndex) => {
    const cellHeights = row.map((cell) =>
      doc.heightOfString(String(cell), { width: colWidth - 2 * padding })
    );
    const rowHeight = Math.max(...cellHeights) + 10;

    if (y + rowHeight > doc.page.height - bottomMargin) {
      doc.addPage();
      y = pageTop;
      drawHeader();
    }

    for (let i = 0; i < colCount; i++) {
      const x = startX + i * colWidth;
      const bg = rowIndex % 2 === 0 ? "#ffffff" : "#f8fafc";

      // Fill background
      doc.rect(x, y, colWidth, rowHeight).fill(bg);

      // Draw border
      doc.rect(x, y, colWidth, rowHeight).stroke("#000000");

      // Draw cell text
      doc.fillColor("black").text(String(row[i] ?? "N/A"), x + padding, y + 5, {
        width: colWidth - 2 * padding,
        align: "left",
      });
    }

    y += rowHeight;
  });

  doc.y = y + 8;
}

// ===== Admin: Get all faculty list =====
app.get(
  "/api/faculty",
  authenticateToken,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const [rows] = await db.query(`
        SELECT f.pin, f.email, p.name
        FROM faculty f
        LEFT JOIN personal_information p ON f.pin = p.pin
      `);
      res.json(rows);
    } catch (err) {
      console.error("Error fetching faculty list:", err);
      res.status(500).json({ message: "Server error fetching faculty" });
    }
  }
);

// ===== Export app =====
export default app;
