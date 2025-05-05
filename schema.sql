-- Create Student table with additional authentication fields
CREATE TABLE Student (
    StudentID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    FirstName TEXT NOT NULL,
    LastName TEXT NOT NULL,
    Email VARCHAR(100) UNIQUE,
    Password VARCHAR(255) NOT NULL, -- Password should be hashed
    totp_secret VARCHAR(32),                
    Otp_Expiry DATETIME,                 -- Expiry for the OTP when using email varification
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create Course table
CREATE TABLE Course (
    CourseID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    UnitCode VARCHAR(20) NOT NULL UNIQUE,
    CourseName VARCHAR(100) NOT NULL,
    CreditPoints INTEGER NOT NULL
);

-- Create StudentCourse rename from studentclass to capture enrollment relationships
CREATE TABLE StudentCourse (
    StudentID INTEGER NOT NULL,
    CourseID INTEGER NOT NULL,
    EnrollmentDate DATE, --CAN be nulll
    PRIMARY KEY (StudentID, CourseID),
    FOREIGN KEY (StudentID) REFERENCES Student(StudentID) ON DELETE CASCADE,
    FOREIGN KEY (CourseID) REFERENCES Course(CourseID) ON DELETE CASCADE
);
--should double check filepath method
CREATE TABLE Assignment (
  AssignmentID   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  CourseID        INTEGER,
  StudentID      INTEGER,
  AssignmentName TEXT    NOT NULL,
  FilePath       TEXT    NOT NULL CHECK (
    FilePath LIKE '/secure_uploads/%/_%.%'                        -- prefix + at least one char + slash + _hashedname.ext
    AND length(substr(FilePath, 17, 64)) = 64                    -- the “hashed” filename (64 chars) starts at position 15
    AND substr(FilePath, 17, 64) NOT LIKE '%/%'                  -- no extra slashes in the hash
    AND (
         substr(FilePath, -3, 3) = '.md'                        -- .md extension
      OR substr(FilePath, -4, 4) IN ('.pdf', '.txt')            -- .pdf or .txt
      OR substr(FilePath, -5, 5) = '.docx'                       -- .docx
    )
  ),
  HoursSpent     REAL,
  Weight         REAL    CHECK (Weight BETWEEN 0 AND 100),
  MarksAchieved  REAL    CHECK (MarksAchieved BETWEEN 0 AND MarksOutOf),
  MarksOutOf     REAL    CHECK (MarksOutOf > 0),
  DueDate        DATE    NOT NULL,
  FOREIGN KEY (CourseID)   REFERENCES Course(CourseID) ON DELETE CASCADE,
  FOREIGN KEY (StudentID) REFERENCES Student(StudentID) ON DELETE CASCADE
);


CREATE TABLE Notes (
  NoteID      INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  StudentID   INTEGER NOT NULL,
  CourseID     INTEGER,
  Title       TEXT,
  Category    TEXT CHECK (Category IN ('Lecture', 'Tutorial', 'Lab', 'Exam', 'Other')),  -- Added constraint for Category
  Description TEXT,
  FilePath    TEXT    NOT NULL CHECK (
    FilePath LIKE '/secure_notes/%/_%.%'                         -- notes folder
    AND length(substr(FilePath, 15, 64)) = 64                   -- hash begins at pos 13
    AND substr(FilePath, 15, 64) NOT LIKE '%/%'                 -- no extra slashes
    AND (
         substr(FilePath, -3, 3) = '.md'                        -- .md
      OR substr(FilePath, -4, 4) IN ('.pdf', '.txt')           -- .pdf or .txt
      OR substr(FilePath, -5, 5) = '.docx'                      -- .docx
    )
  ),
  CreatedAt   DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (StudentID) REFERENCES Student(StudentID) ON DELETE CASCADE,
  FOREIGN KEY (CourseID)   REFERENCES Course(CourseID) ON DELETE SET NULL
);


-- Sharing permissions
CREATE TABLE Share (
    ShareID           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    NoteID            INTEGER NOT NULL,
    OwnerStudentID    INTEGER NOT NULL,
    AccesseeStudentID INTEGER NOT NULL,
    EditPower         INTEGER,
    FOREIGN KEY (NoteID)            REFERENCES Notes(NoteID)            ON DELETE CASCADE,
    FOREIGN KEY (OwnerStudentID)    REFERENCES Student(StudentID)      ON DELETE CASCADE,
    FOREIGN KEY (AccesseeStudentID) REFERENCES Student(StudentID)      ON DELETE CASCADE,
    UNIQUE (NoteID, AccesseeStudentID)
);
