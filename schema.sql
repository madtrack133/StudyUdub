CREATE TABLE Student (
    StudentID INT PRIMARY KEY,
    FirstName VARCHAR(50) NOT NULL,
    LastName VARCHAR(50) NOT NULL,
    Email VARCHAR(100) UNIQUE,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Class (
    ClassID INT PRIMARY KEY,
    UnitCode VARCHAR(20) NOT NULL UNIQUE,
    ClassName VARCHAR(100) NOT NULL,
    CreditPoints INT NOT NULL
);

CREATE TABLE StudentClass (
    StudentID INT,
    ClassID INT,
    EnrollmentDate DATE NOT NULL,
    PRIMARY KEY (StudentID, ClassID),
    FOREIGN KEY (StudentID) REFERENCES Student(StudentID),
    FOREIGN KEY (ClassID) REFERENCES Class(ClassID)
);

CREATE TABLE Assignment (
    AssignmentID INT PRIMARY KEY,
    ClassID INT,
    StudentID INT,
    AssignmentName VARCHAR(100) NOT NULL,
    HoursSpent DECIMAL(5,2),
    Score DECIMAL(5,2) CHECK (Score BETWEEN 0 AND 100),
    Weight DECIMAL(5,2) CHECK (Weight BETWEEN 0 AND 100),
    DueDate DATE NOT NULL,
    FOREIGN KEY (ClassID) REFERENCES Class(ClassID),
    FOREIGN KEY (StudentID) REFERENCES Student(StudentID)
);

CREATE TABLE Notes (
    NoteID INT PRIMARY KEY,
    StudentID INT,
    ClassID INT,
    Title VARCHAR(255),
    FilePath VARCHAR(255) NOT NULL, -- Instead of BLOB, store file path
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (StudentID) REFERENCES Student(StudentID),
    FOREIGN KEY (ClassID) REFERENCES Class(ClassID)
);