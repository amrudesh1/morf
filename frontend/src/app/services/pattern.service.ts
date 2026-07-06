import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, throwError } from 'rxjs';

export interface Pattern {
  name: string;
  regex: string;
  confidence: 'high' | 'medium' | 'low';
  enabled: boolean;
}

export interface PatternFile {
  filename: string;
  patterns: Pattern[];
}

export interface PatternListResponse {
  files: PatternFile[];
  total: number;
}

export interface PatternTestResponse {
  matched: boolean;
  matches: string[];
  count: number;
}

@Injectable({
  providedIn: 'root'
})
export class PatternService {
  private apiUrl = '/api';

  constructor(private http: HttpClient) {}

  // List all pattern files
  listPatterns(): Observable<PatternListResponse> {
    return this.http.get<PatternListResponse>(`${this.apiUrl}/patterns`).pipe(
      catchError(error => {
        console.error('Error listing patterns:', error);
        return throwError(() => error);
      })
    );
  }

  // Get patterns from a specific file
  getPatternFile(filename: string): Observable<{ filename: string; patterns: Pattern[] }> {
    return this.http.get<{ filename: string; patterns: Pattern[] }>(`${this.apiUrl}/patterns/${filename}`).pipe(
      catchError(error => {
        console.error('Error getting pattern file:', error);
        return throwError(() => error);
      })
    );
  }

  // Create a new pattern file
  createPatternFile(filename: string, patterns: Pattern[]): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.apiUrl}/patterns`, {
      filename,
      patterns
    }).pipe(
      catchError(error => {
        console.error('Error creating pattern file:', error);
        return throwError(() => error);
      })
    );
  }

  // Update a pattern file
  updatePatternFile(filename: string, patterns: Pattern[]): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.apiUrl}/patterns/${filename}`, {
      patterns
    }).pipe(
      catchError(error => {
        console.error('Error updating pattern file:', error);
        return throwError(() => error);
      })
    );
  }

  // Delete a pattern file
  deletePatternFile(filename: string): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.apiUrl}/patterns/${filename}`).pipe(
      catchError(error => {
        console.error('Error deleting pattern file:', error);
        return throwError(() => error);
      })
    );
  }

  // Add a pattern to a file
  addPattern(filename: string, pattern: Pattern): Observable<{ message: string }> {
    return this.http.put<{ message: string }>(`${this.apiUrl}/patterns/${filename}/patterns`, pattern).pipe(
      catchError(error => {
        console.error('Error adding pattern:', error);
        return throwError(() => error);
      })
    );
  }

  // Update a pattern in a file
  updatePattern(filename: string, patternName: string, pattern: Pattern): Observable<{ message: string }> {
    return this.http.patch<{ message: string }>(`${this.apiUrl}/patterns/${filename}/patterns/${patternName}`, pattern).pipe(
      catchError(error => {
        console.error('Error updating pattern:', error);
        return throwError(() => error);
      })
    );
  }

  // Delete a pattern from a file
  deletePattern(filename: string, patternName: string): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.apiUrl}/patterns/${filename}/patterns/${patternName}`).pipe(
      catchError(error => {
        console.error('Error deleting pattern:', error);
        return throwError(() => error);
      })
    );
  }

  // Enable/disable a pattern
  enableDisablePattern(filename: string, patternName: string, enabled: boolean): Observable<{ message: string }> {
    return this.http.patch<{ message: string }>(`${this.apiUrl}/patterns/${filename}/patterns/${patternName}/enable`, {
      enabled
    }).pipe(
      catchError(error => {
        console.error('Error enabling/disabling pattern:', error);
        return throwError(() => error);
      })
    );
  }

  // Test a pattern
  testPattern(filename: string, patternName: string, sampleText: string): Observable<PatternTestResponse> {
    return this.http.post<PatternTestResponse>(`${this.apiUrl}/patterns/${filename}/test`, {
      pattern_name: patternName,
      sample_text: sampleText
    }).pipe(
      catchError(error => {
        console.error('Error testing pattern:', error);
        return throwError(() => error);
      })
    );
  }
}

