-- Create Student table with additional authentication fields
CREATE TABLE Student (
    StudentID INT PRIMARY KEY,
    FirstName VARCHAR(50) NOT NULL,
    LastName VARCHAR(50) NOT NULL,
    Email VARCHAR(100) UNIQUE,
    Password VARCHAR(255) NOT NULL,      -- Password (typically hashed)
    Otp_Code VARCHAR(10),                -- One-time password code (optional)
    Otp_Expiry DATETIME,                 -- Expiry for the OTP
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create Class table
CREATE TABLE Class (
    ClassID INT PRIMARY KEY,
    UnitCode VARCHAR(20) NOT NULL UNIQUE,
    ClassName VARCHAR(100) NOT NULL,
    CreditPoints INT NOT NULL
);

-- Create StudentClass to capture enrollment relationships
CREATE TABLE StudentClass (
    StudentID INT,
    ClassID INT,
    EnrollmentDate DATE NOT NULL,
    PRIMARY KEY (StudentID, ClassID),
    FOREIGN KEY (StudentID) REFERENCES Student(StudentID),
    FOREIGN KEY (ClassID) REFERENCES Class(ClassID)
);

CREATE TABLE Assignment (
  AssignmentID   INTEGER PRIMARY KEY,
  ClassID        INTEGER,
  StudentID      INTEGER,
  AssignmentName TEXT    NOT NULL,
  FilePath       TEXT    NOT NULL CHECK (
    FilePath LIKE '/secure_uploads/%/_%.%'                        -- prefix + at least one char + slash + _hashedname.ext
    AND length(substr(FilePath, 15, 64)) = 64                    -- the “hashed” filename (64 chars) starts at position 15
    AND substr(FilePath, 15, 64) NOT LIKE '%/%'                  -- no extra slashes in the hash
    AND (
         substr(FilePath, -4, 4) IN ('.pdf', '.txt')            -- ends in .pdf or .txt
      OR substr(FilePath, -5, 5) = '.docx'                       -- or .docx (5-char extension)
    )
  ),
  HoursSpent     REAL,
  Score          REAL    CHECK (Score  BETWEEN 0 AND 100),
  Weight         REAL    CHECK (Weight BETWEEN 0 AND 100),
  DueDate        DATE    NOT NULL,
  FOREIGN KEY (ClassID)   REFERENCES Class(ClassID),
  FOREIGN KEY (StudentID) REFERENCES Student(StudentID)
);


CREATE TABLE Notes (
  NoteID      INTEGER PRIMARY KEY,
  StudentID   INTEGER,
  ClassID     INTEGER,
  Title       TEXT,
  FilePath    TEXT    NOT NULL CHECK (
    FilePath LIKE '/secure_notes/%/_%.%'                         -- notes folder
    AND length(substr(FilePath, 13, 64)) = 64                   -- hash begins at pos 13
    AND substr(FilePath, 13, 64) NOT LIKE '%/%'                 -- no extra slashes
    AND (
         substr(FilePath, -3, 3) = '.md'                        -- .md (3-char extension)
      OR substr(FilePath, -4, 4) IN ('.txt', '.docx')           -- or .txt/.docx
    )
  ),
  CreatedAt   DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (StudentID) REFERENCES Student(StudentID),
  FOREIGN KEY (ClassID)   REFERENCES Class(ClassID)
);


-- Create Share table to manage sharing permissions between students
CREATE TABLE Share (
    ShareID INT PRIMARY KEY,
    OwnerStudentID INT,                     -- The student who owns the resource
    AccesseeStudentID INT,                  -- The student with whom the resource is shared
    EditPower BOOLEAN,                      -- TRUE if the accessee is allowed to edit
    FOREIGN KEY (OwnerStudentID) REFERENCES Student(StudentID),
    FOREIGN KEY (AccesseeStudentID) REFERENCES Student(StudentID)
);
