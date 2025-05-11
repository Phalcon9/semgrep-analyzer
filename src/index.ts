import express, { Request, Response } from "express";
import { exec } from "child_process";
import path from "path";
import fs from "fs";
import simpleGit from "simple-git";
import cors from "cors";

// Initialize the Express app
const app = express();
app.use(express.json({ limit: "10mb" })); // Increase JSON payload limit

app.use(
  cors({
    origin: "*", // Consider restricting this in production
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

const git = simpleGit();
const TEMP_DIR = path.join(__dirname, "temp");

// Ensure temp directory exists with proper permissions
if (!fs.existsSync(TEMP_DIR)) {
  try {
    fs.mkdirSync(TEMP_DIR, { recursive: true, mode: 0o777 });
    console.log(`Created temp directory: ${TEMP_DIR}`);
  } catch (error) {
    console.error(`Error creating temp directory: ${error}`);
  }
}

// Test file system permissions
try {
  const testFile = path.join(TEMP_DIR, "test.txt");
  fs.writeFileSync(testFile, "test");
  console.log(`Successfully wrote test file: ${testFile}`);
  fs.unlinkSync(testFile);
  console.log(`Successfully deleted test file: ${testFile}`);
} catch (error) {
  console.error(`File system permission test failed: ${error}`);
}

// Test if semgrep is available
try {
  exec("semgrep --version", (error, stdout, stderr) => {
    if (error) {
      console.error(`Error checking semgrep version: ${error.message}`);
      console.error(`stderr: ${stderr}`);
    } else {
      console.log(`Semgrep version: ${stdout.trim()}`);
    }
  });
} catch (error) {
  console.error(`Failed to execute semgrep version check: ${error}`);
}

// Helper function to recursively list all files in a directory
function listAllFiles(dir: string, fileList: string[] = []): string[] {
  try {
    const files = fs.readdirSync(dir);

    files.forEach((file) => {
      const filePath = path.join(dir, file);
      try {
        if (fs.statSync(filePath).isDirectory()) {
          // Skip .git directory
          if (file !== ".git") {
            fileList = listAllFiles(filePath, fileList);
          }
        } else {
          fileList.push(filePath);
        }
      } catch (error) {
        console.error(`Error processing file ${filePath}: ${error}`);
      }
    });

    return fileList;
  } catch (error) {
    console.error(`Error listing files in directory ${dir}: ${error}`);
    return fileList;
  }
}

// Helper function to clone the GitHub repository dynamically
async function cloneRepository(gitUrl: string): Promise<string> {
  const repoName = gitUrl.split("/").pop()?.replace(".git", "") || "repo";
  const repoPath = path.join(TEMP_DIR, repoName);

  console.log(`Cloning repository to: ${repoPath}`);

  // Remove any previous clone of the repository
  if (fs.existsSync(repoPath)) {
    console.log(`Removing existing directory: ${repoPath}`);
    try {
      fs.rmSync(repoPath, { recursive: true, force: true });
    } catch (error) {
      console.error(`Error removing directory: ${error}`);
      throw new Error(`Failed to remove existing directory: ${error}`);
    }
  }

  try {
    // Clone the repository
    console.log(`Starting clone of: ${gitUrl}`);
    await git.clone(gitUrl, repoPath);
    console.log(`Successfully cloned to: ${repoPath}`);

    // Verify the clone
    if (!fs.existsSync(repoPath)) {
      throw new Error(
        `Repository directory not found after clone: ${repoPath}`
      );
    }

    return repoPath;
  } catch (error: any) {
    console.error(`Error cloning repository: ${error.message}`);
    throw new Error(`Failed to clone repository: ${error.message}`);
  }
}

// Helper function to run Semgrep on the cloned repository
function runSemgrep(directory: string): Promise<string> {
  return new Promise((resolve, reject) => {
    console.log(`Running Semgrep on directory: ${directory}`);

    // Verify directory exists
    if (!fs.existsSync(directory)) {
      const error = `Directory does not exist: ${directory}`;
      console.error(error);
      reject(new Error(error));
      return;
    }

    // Use the custom config from project root
    const semgrepConfigPath = path.join(process.cwd(), ".semgrep-custom.yml");

    if (!fs.existsSync(semgrepConfigPath)) {
      const error = `Semgrep configuration not found at: ${semgrepConfigPath}`;
      console.error(error);
      reject(new Error(error));
      return;
    }

    // Validate semgrep config
    console.log(`Validating semgrep config at: ${semgrepConfigPath}`);
    exec(
      `semgrep --validate --config "${semgrepConfigPath}"`,
      (validationError) => {
        if (validationError) {
          const error = `Invalid Semgrep configuration: ${validationError.message}`;
          console.error(error);
          reject(new Error(error));
          return;
        }

        console.log("Semgrep configuration is valid");
        const semgrepCommand = `cd "${directory}" && semgrep scan --config "${semgrepConfigPath}" --verbose --json .`;

        exec(
          semgrepCommand,
          {
            maxBuffer: 10 * 1024 * 1024, // 10MB buffer
            timeout: 300000, // 5 minutes timeout
          },
          (error, stdout, stderr) => {
            // Attempt to parse the output as JSON regardless of exit code
            try {
              const results = JSON.parse(stdout);

              // Check if we have valid results
              if (results && (results.results || results.errors)) {
                console.log(`Found ${results.results?.length || 0} results`);
                resolve(stdout);
              } else {
                reject(new Error("Invalid Semgrep output format"));
              }
            } catch (parseError) {
              console.error(`Error parsing Semgrep output: ${parseError}`);
              console.error(`Stdout: ${stdout}`);
              console.error(`Stderr: ${stderr}`);
              reject(
                new Error(`Failed to parse Semgrep output: ${parseError}`)
              );
            }
          }
        );
      }
    );
  });
}

// POST /analyze: Endpoint to receive a GitHub repository URL for analysis
app.post("/analyze", async (req: Request, res: Response) => {
  console.log("Received analyze request");

  const { gitUrl } = req.body;

  if (!gitUrl) {
    return res
      .status(400)
      .json({ error: "Please provide a gitUrl in the request body." });
  }

  console.log(`Received analysis request for: ${gitUrl}`);

  try {
    // Step 1: Clone the repository dynamically
    console.log("Starting repository clone");
    const repoPath = await cloneRepository(gitUrl);
    console.log("Clone successful");

    // Step 2: Run Semgrep on the cloned codebase
    console.log("Starting Semgrep analysis");
    const semgrepOutput = await runSemgrep(repoPath);
    console.log("Semgrep analysis complete");

    // Step 3: Parse and return the vulnerabilities found
    let vulnerabilities;
    try {
      vulnerabilities = JSON.parse(semgrepOutput);
      console.log(
        `Analysis complete. Found ${
          vulnerabilities.results?.length || 0
        } results`
      );
    } catch (parseError) {
      console.error(`Error parsing Semgrep output: ${parseError}`);
      console.error(`Raw output: ${semgrepOutput}`);
      vulnerabilities = {
        error: "Failed to parse Semgrep output",
        results: [],
      };
    }

    // Send back the results
    res.json({ vulnerabilities });

    // Step 4: Cleanup the cloned repository
    try {
      console.log(`Cleaning up: ${repoPath}`);
      fs.rmSync(repoPath, { recursive: true, force: true });
      console.log("Cleanup complete");
    } catch (cleanupError) {
      console.error(`Error during cleanup: ${cleanupError}`);
    }
  } catch (error: any) {
    console.error(`Analysis failed: ${error.message}`);
    res.status(500).json({ error: `Analysis failed: ${error.message}` });
  }
});

// GET /health: Health check endpoint
app.get("/health", (req: Request, res: Response) => {
  res.json({
    status: "healthy",
    checks: {
      tempDir: fs.existsSync(TEMP_DIR),
      semgrep: true, // We'll assume it's available; the actual check happens at startup
    },
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Temporary directory: ${TEMP_DIR}`);
});

// Handle graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully");
  // Clean up temp directory
  if (fs.existsSync(TEMP_DIR)) {
    try {
      fs.rmSync(TEMP_DIR, { recursive: true, force: true });
      console.log(`Cleaned up temp directory: ${TEMP_DIR}`);
    } catch (error) {
      console.error(`Error cleaning up temp directory: ${error}`);
    }
  }
  process.exit(0);
});
