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

-- Create Assignment table with added FilePath column
CREATE TABLE Assignment (
    AssignmentID INT PRIMARY KEY,
    ClassID INT,
    StudentID INT,
    AssignmentName VARCHAR(100) NOT NULL,
    FilePath VARCHAR(255) NOT NULL,        -- Stores the file path for assignment submission
    HoursSpent DECIMAL(5,2),
    Score DECIMAL(5,2) CHECK (Score BETWEEN 0 AND 100),
    Weight DECIMAL(5,2) CHECK (Weight BETWEEN 0 AND 100),
    DueDate DATE NOT NULL,
    FOREIGN KEY (ClassID) REFERENCES Class(ClassID),
    FOREIGN KEY (StudentID) REFERENCES Student(StudentID)
);

-- Create Notes table for student notes (file stored as path)
CREATE TABLE Notes (
    NoteID INT PRIMARY KEY,
    StudentID INT,
    ClassID INT,
    Title VARCHAR(255),
    FilePath VARCHAR(255) NOT NULL,         -- File path to the note file
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (StudentID) REFERENCES Student(StudentID),
    FOREIGN KEY (ClassID) REFERENCES Class(ClassID)
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
