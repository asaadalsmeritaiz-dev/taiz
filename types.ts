export interface User {
  _id: string;
  name: string;
  email: string;
  role: 'admin' | 'student';
  passwordHash: string;
}

export interface Student {
  _id: string;
  userId: string;
  fullName: {
    firstName: string;
    middleName: string;
    lastName: string;
    familyName: string;
  };
  academicId: string;
  photo: string; // Base64 or placeholder URL
  documents: { name: string; content: string; type: string }[]; // Base64 files
  departmentId: string;
  status: 'Active' | 'Suspended' | 'Graduated' | 'On Leave';
  createdAt: string;
}

export interface Department {
  _id: string;
  name: string;
  description: string;
  headOfDepartment: string;
}

export interface LectureAttendance {
  studentId: string;
  timestamp: string;
}

export interface Lecture {
  _id: string;
  departmentId: string;
  courseName: string;
  lectureNumber: number;
  instructor: string;
  youtubeLink: string;
  pdfContent: string; // text description or base64
  diagrams: string[]; // array of base64 images
  assignmentId?: string;
  attendance: LectureAttendance[];
}

export interface AssignmentSubmission {
  studentId: string;
  fileUrl: string; // base64 pdf content
  fileName: string;
  grade?: number; // score
  submittedAt: string;
}

export interface Assignment {
  _id: string;
  lectureId: string;
  title: string;
  description: string;
  dueDate: string;
  submissions: AssignmentSubmission[];
}

export interface ExamQuestion {
  id: string;
  type: 'mcq' | 'essay';
  questionText: string;
  options?: string[]; // only for mcq
  correctAnswer?: string; // only for mcq
}

export interface ExamResult {
  studentId: string;
  answers: { questionId: string; answerText: string }[];
  score?: number; // final grade (auto graded mcqs + manual essay grading)
  cameraRecording?: string; // base64 or video url
  screenRecording?: string; // base64 or video url
  submittedAt: string;
}

export interface Exam {
  _id: string;
  departmentId: string;
  courseName: string;
  title?: string;
  date: string;
  time: string;
  duration: number; // in minutes
  maxScore?: number;
  questions: ExamQuestion[];
  results: ExamResult[];
  resultsPublished?: boolean;
}

export interface FeeReceipt {
  fileUrl: string; // base64 receipt
  fileName: string;
  uploadedAt: string;
}

export interface Fee {
  _id: string;
  studentId: string;
  semester: string;
  totalFees: number;
  amountPaid: number;
  remaining: number;
  receipts: FeeReceipt[];
}

export interface Notification {
  _id: string;
  departmentId: string | null; // null for global
  title: string;
  message: string;
  createdAt: string;
  readBy: string[]; // array of studentIds
}

export interface Complaint {
  _id: string;
  studentId: string;
  subject: string;
  description: string;
  attachments: { name: string; content: string; type: string }[]; // base64 files
  status: 'pending' | 'in-progress' | 'resolved';
  response?: string;
  createdAt: string;
}

export interface DashboardStats {
  totalStudents: number;
  totalDepartments: number;
  upcomingExams: number;
}
