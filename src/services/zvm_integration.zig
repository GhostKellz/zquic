//! ZVM WASM Runtime Integration over QUIC
//!
//! This module provides integration between ZQUIC transport and ZVM (Zig Virtual Machine)
//! for executing WebAssembly smart contracts over post-quantum QUIC connections.

const std = @import("std");
const Error = @import("../utils/error.zig");
const Connection = @import("../core/connection.zig").Connection;
const Stream = @import("../core/stream.zig").Stream;

/// WASM execution request over QUIC
pub const WasmExecutionRequest = struct {
    /// Unique request ID
    request_id: u64,
    /// WASM module bytecode
    module_bytecode: []const u8,
    /// Function name to execute
    function_name: []const u8,
    /// Function arguments (serialized)
    arguments: []const u8,
    /// Gas limit for execution
    gas_limit: u64,
    /// Memory limit in bytes
    memory_limit: u32,
    /// Execution timeout in milliseconds
    timeout_ms: u32,
    /// Caller's address (for authentication)
    caller_address: []const u8,
    
    pub fn serialize(self: *const WasmExecutionRequest, allocator: std.mem.Allocator) ![]u8 {
        // Simple serialization format:
        // [request_id: 8][module_len: 4][module_bytecode: var][function_name_len: 2][function_name: var]
        // [args_len: 4][arguments: var][gas_limit: 8][memory_limit: 4][timeout_ms: 4]
        // [caller_addr_len: 2][caller_address: var]
        
        const total_size = 8 + 4 + self.module_bytecode.len + 2 + self.function_name.len +
                          4 + self.arguments.len + 8 + 4 + 4 + 2 + self.caller_address.len;
        
        const buffer = try allocator.alloc(u8, total_size);
        var offset: usize = 0;
        
        // Request ID
        std.mem.writeInt(u64, buffer[offset..offset + 8], self.request_id, .big);
        offset += 8;
        
        // Module bytecode
        std.mem.writeInt(u32, buffer[offset..offset + 4], @intCast(self.module_bytecode.len), .big);
        offset += 4;
        @memcpy(buffer[offset..offset + self.module_bytecode.len], self.module_bytecode);
        offset += self.module_bytecode.len;
        
        // Function name
        std.mem.writeInt(u16, buffer[offset..offset + 2], @intCast(self.function_name.len), .big);
        offset += 2;
        @memcpy(buffer[offset..offset + self.function_name.len], self.function_name);
        offset += self.function_name.len;
        
        // Arguments
        std.mem.writeInt(u32, buffer[offset..offset + 4], @intCast(self.arguments.len), .big);
        offset += 4;
        @memcpy(buffer[offset..offset + self.arguments.len], self.arguments);
        offset += self.arguments.len;
        
        // Gas limit
        std.mem.writeInt(u64, buffer[offset..offset + 8], self.gas_limit, .big);
        offset += 8;
        
        // Memory limit
        std.mem.writeInt(u32, buffer[offset..offset + 4], self.memory_limit, .big);
        offset += 4;
        
        // Timeout
        std.mem.writeInt(u32, buffer[offset..offset + 4], self.timeout_ms, .big);
        offset += 4;
        
        // Caller address
        std.mem.writeInt(u16, buffer[offset..offset + 2], @intCast(self.caller_address.len), .big);
        offset += 2;
        @memcpy(buffer[offset..offset + self.caller_address.len], self.caller_address);
        
        return buffer;
    }
    
    pub fn deserialize(data: []const u8, allocator: std.mem.Allocator) !WasmExecutionRequest {
        if (data.len < 28) return Error.ZquicError.InvalidData; // Minimum size check
        
        var offset: usize = 0;
        
        // Request ID
        const request_id = std.mem.readInt(u64, data[offset..offset + 8], .big);
        offset += 8;
        
        // Module bytecode
        const module_len = std.mem.readInt(u32, data[offset..offset + 4], .big);
        offset += 4;
        if (offset + module_len > data.len) return Error.ZquicError.InvalidData;
        const module_bytecode = try allocator.dupe(u8, data[offset..offset + module_len]);
        offset += module_len;
        
        // Function name
        if (offset + 2 > data.len) return Error.ZquicError.InvalidData;
        const function_name_len = std.mem.readInt(u16, data[offset..offset + 2], .big);
        offset += 2;
        if (offset + function_name_len > data.len) return Error.ZquicError.InvalidData;
        const function_name = try allocator.dupe(u8, data[offset..offset + function_name_len]);
        offset += function_name_len;
        
        // Arguments
        if (offset + 4 > data.len) return Error.ZquicError.InvalidData;
        const args_len = std.mem.readInt(u32, data[offset..offset + 4], .big);
        offset += 4;
        if (offset + args_len > data.len) return Error.ZquicError.InvalidData;
        const arguments = try allocator.dupe(u8, data[offset..offset + args_len]);
        offset += args_len;
        
        // Gas limit
        if (offset + 8 > data.len) return Error.ZquicError.InvalidData;
        const gas_limit = std.mem.readInt(u64, data[offset..offset + 8], .big);
        offset += 8;
        
        // Memory limit
        if (offset + 4 > data.len) return Error.ZquicError.InvalidData;
        const memory_limit = std.mem.readInt(u32, data[offset..offset + 4], .big);
        offset += 4;
        
        // Timeout
        if (offset + 4 > data.len) return Error.ZquicError.InvalidData;
        const timeout_ms = std.mem.readInt(u32, data[offset..offset + 4], .big);
        offset += 4;
        
        // Caller address
        if (offset + 2 > data.len) return Error.ZquicError.InvalidData;
        const caller_addr_len = std.mem.readInt(u16, data[offset..offset + 2], .big);
        offset += 2;
        if (offset + caller_addr_len > data.len) return Error.ZquicError.InvalidData;
        const caller_address = try allocator.dupe(u8, data[offset..offset + caller_addr_len]);
        
        return WasmExecutionRequest{
            .request_id = request_id,
            .module_bytecode = module_bytecode,
            .function_name = function_name,
            .arguments = arguments,
            .gas_limit = gas_limit,
            .memory_limit = memory_limit,
            .timeout_ms = timeout_ms,
            .caller_address = caller_address,
        };
    }
    
    pub fn deinit(self: *WasmExecutionRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.module_bytecode);
        allocator.free(self.function_name);
        allocator.free(self.arguments);
        allocator.free(self.caller_address);
    }
};

/// WASM execution result
pub const WasmExecutionResult = struct {
    /// Request ID this result corresponds to
    request_id: u64,
    /// Execution status
    status: ExecutionStatus,
    /// Return value (serialized)
    return_value: []const u8,
    /// Gas consumed during execution
    gas_consumed: u64,
    /// Execution time in microseconds
    execution_time_us: u64,
    /// Error message if execution failed
    error_message: []const u8,
    /// Modified state (if any)
    modified_state: []const u8,
    
    pub const ExecutionStatus = enum(u8) {
        success = 0,
        out_of_gas = 1,
        out_of_memory = 2,
        timeout = 3,
        invalid_function = 4,
        runtime_error = 5,
        invalid_module = 6,
        authentication_failed = 7,
    };
    
    pub fn serialize(self: *const WasmExecutionResult, allocator: std.mem.Allocator) ![]u8 {
        const total_size = 8 + 1 + 4 + self.return_value.len + 8 + 8 + 
                          4 + self.error_message.len + 4 + self.modified_state.len;
        
        const buffer = try allocator.alloc(u8, total_size);
        var offset: usize = 0;
        
        // Request ID
        std.mem.writeInt(u64, buffer[offset..offset + 8], self.request_id, .big);
        offset += 8;
        
        // Status
        buffer[offset] = @intFromEnum(self.status);
        offset += 1;
        
        // Return value
        std.mem.writeInt(u32, buffer[offset..offset + 4], @intCast(self.return_value.len), .big);
        offset += 4;
        @memcpy(buffer[offset..offset + self.return_value.len], self.return_value);
        offset += self.return_value.len;
        
        // Gas consumed
        std.mem.writeInt(u64, buffer[offset..offset + 8], self.gas_consumed, .big);
        offset += 8;
        
        // Execution time
        std.mem.writeInt(u64, buffer[offset..offset + 8], self.execution_time_us, .big);
        offset += 8;
        
        // Error message
        std.mem.writeInt(u32, buffer[offset..offset + 4], @intCast(self.error_message.len), .big);
        offset += 4;
        @memcpy(buffer[offset..offset + self.error_message.len], self.error_message);
        offset += self.error_message.len;
        
        // Modified state
        std.mem.writeInt(u32, buffer[offset..offset + 4], @intCast(self.modified_state.len), .big);
        offset += 4;
        @memcpy(buffer[offset..offset + self.modified_state.len], self.modified_state);
        
        return buffer;
    }
    
    pub fn deserialize(data: []const u8, allocator: std.mem.Allocator) !WasmExecutionResult {
        if (data.len < 33) return Error.ZquicError.InvalidData; // Minimum size
        
        var offset: usize = 0;
        
        // Request ID
        const request_id = std.mem.readInt(u64, data[offset..offset + 8], .big);
        offset += 8;
        
        // Status
        const status = @as(ExecutionStatus, @enumFromInt(data[offset]));
        offset += 1;
        
        // Return value
        const return_value_len = std.mem.readInt(u32, data[offset..offset + 4], .big);
        offset += 4;
        if (offset + return_value_len > data.len) return Error.ZquicError.InvalidData;
        const return_value = try allocator.dupe(u8, data[offset..offset + return_value_len]);
        offset += return_value_len;
        
        // Gas consumed
        if (offset + 8 > data.len) return Error.ZquicError.InvalidData;
        const gas_consumed = std.mem.readInt(u64, data[offset..offset + 8], .big);
        offset += 8;
        
        // Execution time
        if (offset + 8 > data.len) return Error.ZquicError.InvalidData;
        const execution_time_us = std.mem.readInt(u64, data[offset..offset + 8], .big);
        offset += 8;
        
        // Error message
        if (offset + 4 > data.len) return Error.ZquicError.InvalidData;
        const error_msg_len = std.mem.readInt(u32, data[offset..offset + 4], .big);
        offset += 4;
        if (offset + error_msg_len > data.len) return Error.ZquicError.InvalidData;
        const error_message = try allocator.dupe(u8, data[offset..offset + error_msg_len]);
        offset += error_msg_len;
        
        // Modified state
        if (offset + 4 > data.len) return Error.ZquicError.InvalidData;
        const state_len = std.mem.readInt(u32, data[offset..offset + 4], .big);
        offset += 4;
        if (offset + state_len > data.len) return Error.ZquicError.InvalidData;
        const modified_state = try allocator.dupe(u8, data[offset..offset + state_len]);
        
        return WasmExecutionResult{
            .request_id = request_id,
            .status = status,
            .return_value = return_value,
            .gas_consumed = gas_consumed,
            .execution_time_us = execution_time_us,
            .error_message = error_message,
            .modified_state = modified_state,
        };
    }
    
    pub fn deinit(self: *WasmExecutionResult, allocator: std.mem.Allocator) void {
        allocator.free(self.return_value);
        allocator.free(self.error_message);
        allocator.free(self.modified_state);
    }
};

/// ZVM QUIC Server for handling smart contract execution requests
pub const ZvmQuicServer = struct {
    allocator: std.mem.Allocator,
    connection: *Connection,
    active_executions: std.HashMap(u64, *ActiveExecution, std.hash_map.DefaultHashContext(u64), std.hash_map.default_max_load_percentage),
    next_execution_id: u64,
    max_concurrent_executions: u32,
    default_gas_limit: u64,
    default_memory_limit: u32,
    default_timeout_ms: u32,
    
    const ActiveExecution = struct {
        request: WasmExecutionRequest,
        start_time: i64,
        thread_handle: ?std.Thread,
    };
    
    pub fn init(allocator: std.mem.Allocator, connection: *Connection) !ZvmQuicServer {
        return ZvmQuicServer{
            .allocator = allocator,
            .connection = connection,
            .active_executions = std.HashMap(u64, *ActiveExecution, std.hash_map.DefaultHashContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .next_execution_id = 1,
            .max_concurrent_executions = 100,
            .default_gas_limit = 1_000_000,
            .default_memory_limit = 64 * 1024 * 1024, // 64MB
            .default_timeout_ms = 30_000, // 30 seconds
        };
    }
    
    pub fn deinit(self: *ZvmQuicServer) void {
        // Wait for all active executions to complete
        var iterator = self.active_executions.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.*.thread_handle) |handle| {
                handle.join();
            }
            entry.value_ptr.*.request.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        
        self.active_executions.deinit();
    }
    
    /// Start the ZVM QUIC server
    pub fn start(self: *ZvmQuicServer) !void {
        std.debug.print("🚀 ZVM QUIC Server starting...\n", .{});
        std.debug.print("  Max concurrent executions: {}\n", .{self.max_concurrent_executions});
        std.debug.print("  Default gas limit: {}\n", .{self.default_gas_limit});
        std.debug.print("  Default memory limit: {} MB\n", .{self.default_memory_limit / (1024 * 1024)});
        std.debug.print("  Default timeout: {} ms\n", .{self.default_timeout_ms});
        
        // Main server loop
        while (true) {
            // Wait for incoming WASM execution requests
            const request_data = try self.receiveRequest();
            defer self.allocator.free(request_data);
            
            // Parse the request
            var request = WasmExecutionRequest.deserialize(request_data, self.allocator) catch |err| {
                std.debug.print("Failed to parse WASM execution request: {}\n", .{err});
                continue;
            };
            
            // Check if we can accept more executions
            if (self.active_executions.count() >= self.max_concurrent_executions) {
                // Send busy response
                const busy_result = WasmExecutionResult{
                    .request_id = request.request_id,
                    .status = .runtime_error,
                    .return_value = "",
                    .gas_consumed = 0,
                    .execution_time_us = 0,
                    .error_message = "Server busy, try again later",
                    .modified_state = "",
                };
                
                try self.sendResult(busy_result);
                request.deinit(self.allocator);
                continue;
            }
            
            // Create active execution entry
            const active_execution = try self.allocator.create(ActiveExecution);
            active_execution.* = ActiveExecution{
                .request = request,
                .start_time = std.time.milliTimestamp(),
                .thread_handle = null,
            };
            
            // Store the execution
            try self.active_executions.put(request.request_id, active_execution);
            
            // Start execution in a separate thread for async processing
            const thread = try std.Thread.spawn(.{}, executeWasmAsync, .{ self, request.request_id });
            active_execution.thread_handle = thread;
            
            std.debug.print("Started WASM execution {} (function: {s})\n", .{ request.request_id, request.function_name });
        }
    }
    
    /// Execute a WASM module asynchronously
    fn executeWasmAsync(self: *ZvmQuicServer, request_id: u64) void {
        defer {
            // Clean up the execution
            if (self.active_executions.get(request_id)) |active_execution| {
                active_execution.request.deinit(self.allocator);
                self.allocator.destroy(active_execution);
                _ = self.active_executions.remove(request_id);
            }
        }
        
        const active_execution = self.active_executions.get(request_id) orelse return;
        const request = active_execution.request;
        
        const start_time = std.time.microTimestamp();
        
        // Execute the WASM module (placeholder implementation)
        const result = self.executeWasmModule(request) catch |err| {
            const error_msg = switch (err) {
                Error.ZquicError.OutOfMemory => "Out of memory",
                Error.ZquicError.Timeout => "Execution timeout",
                Error.ZquicError.InvalidData => "Invalid WASM module",
                else => "Unknown execution error",
            };
            
            WasmExecutionResult{
                .request_id = request_id,
                .status = .runtime_error,
                .return_value = "",
                .gas_consumed = 0,
                .execution_time_us = @intCast(std.time.microTimestamp() - start_time),
                .error_message = error_msg,
                .modified_state = "",
            };
        };
        
        // Send the result back
        self.sendResult(result) catch |err| {
            std.debug.print("Failed to send WASM execution result: {}\n", .{err});
        };
        
        std.debug.print("Completed WASM execution {} in {} μs\n", .{ request_id, result.execution_time_us });
    }
    
    /// Execute a WASM module (placeholder implementation)
    fn executeWasmModule(self: *ZvmQuicServer, request: WasmExecutionRequest) !WasmExecutionResult {
        _ = self;
        
        const start_time = std.time.microTimestamp();
        
        // Placeholder WASM execution logic
        // In a real implementation, this would:
        // 1. Validate the WASM module bytecode
        // 2. Initialize ZVM with gas and memory limits
        // 3. Load the module into ZVM
        // 4. Call the specified function with arguments
        // 5. Monitor gas consumption and execution time
        // 6. Return the result or error
        
        std.debug.print("Executing WASM function: {s}\n", .{request.function_name});
        std.debug.print("  Module size: {} bytes\n", .{request.module_bytecode.len});
        std.debug.print("  Arguments size: {} bytes\n", .{request.arguments.len});
        std.debug.print("  Gas limit: {}\n", .{request.gas_limit});
        std.debug.print("  Memory limit: {} bytes\n", .{request.memory_limit});
        std.debug.print("  Timeout: {} ms\n", .{request.timeout_ms});
        
        // Simulate execution time
        std.time.sleep(1_000_000); // 1ms
        
        const end_time = std.time.microTimestamp();
        const execution_time = @as(u64, @intCast(end_time - start_time));
        
        // Simulate successful execution
        const return_value = "42"; // Placeholder return value
        const gas_consumed = request.gas_limit / 10; // Simulate 10% gas usage
        
        return WasmExecutionResult{
            .request_id = request.request_id,
            .status = .success,
            .return_value = return_value,
            .gas_consumed = gas_consumed,
            .execution_time_us = execution_time,
            .error_message = "",
            .modified_state = "",
        };
    }
    
    /// Receive a WASM execution request over QUIC
    fn receiveRequest(self: *ZvmQuicServer) ![]u8 {
        // Placeholder implementation
        // In a real implementation, this would read from a QUIC stream
        
        // For testing, create a dummy request
        const dummy_request = WasmExecutionRequest{
            .request_id = 1,
            .module_bytecode = &[_]u8{0x00, 0x61, 0x73, 0x6d}, // WASM magic number
            .function_name = "main",
            .arguments = &[_]u8{0x01, 0x02, 0x03},
            .gas_limit = 1_000_000,
            .memory_limit = 1024 * 1024,
            .timeout_ms = 5000,
            .caller_address = &[_]u8{0xde, 0xad, 0xbe, 0xef},
        };
        
        return try dummy_request.serialize(self.allocator);
    }
    
    /// Send a WASM execution result over QUIC
    fn sendResult(self: *ZvmQuicServer, result: WasmExecutionResult) !void {
        // Placeholder implementation
        // In a real implementation, this would send over a QUIC stream
        
        const serialized = try result.serialize(self.allocator);
        defer self.allocator.free(serialized);
        
        std.debug.print("Sending WASM execution result {} ({} bytes)\n", .{ result.request_id, serialized.len });
    }
    
    /// Get statistics about active executions
    pub fn getStats(self: *ZvmQuicServer) ExecutionStats {
        var total_gas_consumed: u64 = 0;
        var oldest_execution_time: i64 = std.time.milliTimestamp();
        
        var iterator = self.active_executions.iterator();
        while (iterator.next()) |entry| {
            const execution = entry.value_ptr.*;
            if (execution.start_time < oldest_execution_time) {
                oldest_execution_time = execution.start_time;
            }
            total_gas_consumed += execution.gas_consumed;
        }
        
        return ExecutionStats{
            .active_executions = @intCast(self.active_executions.count()),
            .total_executions_started = self.next_execution_id - 1,
            .total_gas_consumed = total_gas_consumed,
            .oldest_execution_age_ms = if (self.active_executions.count() > 0) 
                @intCast(std.time.milliTimestamp() - oldest_execution_time) else 0,
        };
    }
    
    pub const ExecutionStats = struct {
        active_executions: u32,
        total_executions_started: u64,
        total_gas_consumed: u64,
        oldest_execution_age_ms: u64,
    };
};

/// ZVM QUIC Client for sending smart contract execution requests
pub const ZvmQuicClient = struct {
    allocator: std.mem.Allocator,
    connection: *Connection,
    next_request_id: u64,
    
    pub fn init(allocator: std.mem.Allocator, connection: *Connection) ZvmQuicClient {
        return ZvmQuicClient{
            .allocator = allocator,
            .connection = connection,
            .next_request_id = 1,
        };
    }
    
    /// Execute a WASM function remotely over QUIC
    pub fn executeFunction(
        self: *ZvmQuicClient,
        module_bytecode: []const u8,
        function_name: []const u8,
        arguments: []const u8,
        options: ExecutionOptions,
    ) !WasmExecutionResult {
        const request_id = self.next_request_id;
        self.next_request_id += 1;
        
        const request = WasmExecutionRequest{
            .request_id = request_id,
            .module_bytecode = module_bytecode,
            .function_name = function_name,
            .arguments = arguments,
            .gas_limit = options.gas_limit,
            .memory_limit = options.memory_limit,
            .timeout_ms = options.timeout_ms,
            .caller_address = options.caller_address,
        };
        
        // Serialize and send the request
        const serialized_request = try request.serialize(self.allocator);
        defer self.allocator.free(serialized_request);
        
        try self.sendRequest(serialized_request);
        
        // Wait for the result
        const result_data = try self.receiveResult(request_id, options.timeout_ms);
        defer self.allocator.free(result_data);
        
        return try WasmExecutionResult.deserialize(result_data, self.allocator);
    }
    
    /// Deploy a WASM module and execute its constructor
    pub fn deployModule(
        self: *ZvmQuicClient,
        module_bytecode: []const u8,
        constructor_args: []const u8,
        options: ExecutionOptions,
    ) !WasmExecutionResult {
        return self.executeFunction(module_bytecode, "_constructor", constructor_args, options);
    }
    
    /// Send a request over QUIC
    fn sendRequest(_: *ZvmQuicClient, data: []const u8) !void {
        // Placeholder implementation
        // In a real implementation, this would send over a QUIC stream
        
        std.debug.print("Sending WASM execution request ({} bytes)\n", .{data.len});
    }
    
    /// Receive a result over QUIC
    fn receiveResult(self: *ZvmQuicClient, request_id: u64, timeout_ms: u32) ![]u8 {
        // Placeholder implementation
        // In a real implementation, this would read from a QUIC stream with timeout
        _ = timeout_ms;
        
        // Create a dummy successful result
        const dummy_result = WasmExecutionResult{
            .request_id = request_id,
            .status = .success,
            .return_value = "Hello from WASM!",
            .gas_consumed = 50000,
            .execution_time_us = 1000,
            .error_message = "",
            .modified_state = "",
        };
        
        return try dummy_result.serialize(self.allocator);
    }
    
    pub const ExecutionOptions = struct {
        gas_limit: u64 = 1_000_000,
        memory_limit: u32 = 64 * 1024 * 1024, // 64MB
        timeout_ms: u32 = 30_000, // 30 seconds
        caller_address: []const u8 = &[_]u8{},
    };
};

/// Utility functions for WASM module validation
pub const WasmValidator = struct {
    pub fn validateModule(module_bytecode: []const u8) !bool {
        // Check WASM magic number
        if (module_bytecode.len < 4) return false;
        
        const magic = std.mem.readInt(u32, module_bytecode[0..4], .little);
        if (magic != 0x6d736100) return false; // "\0asm"
        
        // Check version
        if (module_bytecode.len < 8) return false;
        const version = std.mem.readInt(u32, module_bytecode[4..8], .little);
        if (version != 1) return false; // WASM version 1
        
        return true;
    }
    
    pub fn estimateGasUsage(module_bytecode: []const u8, function_name: []const u8) !u64 {
        _ = function_name;
        
        // Simple heuristic: gas usage roughly proportional to module size
        const base_gas = 10000;
        const gas_per_byte = 10;
        
        return base_gas + (module_bytecode.len * gas_per_byte);
    }
    
    pub fn checkSecurityConstraints(module_bytecode: []const u8) !bool {
        // Basic security checks
        if (module_bytecode.len > 10 * 1024 * 1024) return false; // Max 10MB
        
        // TODO: Add more sophisticated security checks:
        // - No imports to dangerous host functions
        // - No infinite loops
        // - Memory access bounds checking
        // - etc.
        
        return true;
    }
};

test "wasm execution request serialization" {
    const allocator = std.testing.allocator;
    
    const original = WasmExecutionRequest{
        .request_id = 42,
        .module_bytecode = &[_]u8{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00},
        .function_name = "test_function",
        .arguments = &[_]u8{0x01, 0x02, 0x03},
        .gas_limit = 1000000,
        .memory_limit = 1024 * 1024,
        .timeout_ms = 5000,
        .caller_address = &[_]u8{0xde, 0xad, 0xbe, 0xef},
    };
    
    const serialized = try original.serialize(allocator);
    defer allocator.free(serialized);
    
    var deserialized = try WasmExecutionRequest.deserialize(serialized, allocator);
    defer deserialized.deinit(allocator);
    
    try std.testing.expectEqual(original.request_id, deserialized.request_id);
    try std.testing.expectEqualSlices(u8, original.module_bytecode, deserialized.module_bytecode);
    try std.testing.expectEqualSlices(u8, original.function_name, deserialized.function_name);
    try std.testing.expectEqual(original.gas_limit, deserialized.gas_limit);
    try std.testing.expectEqual(original.memory_limit, deserialized.memory_limit);
    try std.testing.expectEqual(original.timeout_ms, deserialized.timeout_ms);
}

test "wasm execution result serialization" {
    const allocator = std.testing.allocator;
    
    const original = WasmExecutionResult{
        .request_id = 42,
        .status = .success,
        .return_value = "Hello, World!",
        .gas_consumed = 50000,
        .execution_time_us = 1500,
        .error_message = "",
        .modified_state = "new_state_data",
    };
    
    const serialized = try original.serialize(allocator);
    defer allocator.free(serialized);
    
    var deserialized = try WasmExecutionResult.deserialize(serialized, allocator);
    defer deserialized.deinit(allocator);
    
    try std.testing.expectEqual(original.request_id, deserialized.request_id);
    try std.testing.expectEqual(original.status, deserialized.status);
    try std.testing.expectEqualSlices(u8, original.return_value, deserialized.return_value);
    try std.testing.expectEqual(original.gas_consumed, deserialized.gas_consumed);
    try std.testing.expectEqual(original.execution_time_us, deserialized.execution_time_us);
}

test "wasm module validation" {
    // Valid WASM module header
    const valid_module = [_]u8{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};
    try std.testing.expect(try WasmValidator.validateModule(&valid_module));
    
    // Invalid magic number
    const invalid_magic = [_]u8{0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00};
    try std.testing.expect(!(try WasmValidator.validateModule(&invalid_magic)));
    
    // Too short
    const too_short = [_]u8{0x00, 0x61};
    try std.testing.expect(!(try WasmValidator.validateModule(&too_short)));
}

test "gas usage estimation" {
    const module = [_]u8{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};
    const estimated_gas = try WasmValidator.estimateGasUsage(&module, "test");
    
    // Should be base gas + (module_size * gas_per_byte)
    const expected = 10000 + (8 * 10);
    try std.testing.expectEqual(@as(u64, expected), estimated_gas);
}