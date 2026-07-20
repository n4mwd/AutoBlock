/*
This source file is part of the AutoBlock project.

Copyright (C) 2026 Dennis Hawkins

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

If you use this code in any way, I would love to hear from you.  My email
address is: dennis@galliform.com
*/

// This module manages the trie data structures that hold the IP netblocks.

#include "AutoBlock.h"
#include <time.h>



// First, we need to represent our trie nodes using a traditional struct format. We also
// include a utility function to convert a subnet mask (like 255.255.0.0) into a prefix bit count (like 16).


// Helper to initialize a new node
TrieNode* create_node(void)
{
    TrieNode* node = (TrieNode*)malloc(sizeof(TrieNode));
    if (node)
    {
        memset(node, 0, sizeof(TrieNode));
    }
    return node;
}


// When a broader network covers existing smaller blocks, we need
// to wipe out the subtree branches beneath it to maintain accurate
// data representation and prevent memory leaks.


// Helper to recursively free a node and all its children
void free_subtree(TrieNode* node)
{
    if (!node) return;
    free_subtree(node->children[0]);
    free_subtree(node->children[1]);
    node->children[0] = node->children[1] = NULL;
    free(node);
}



// Inserts a netblock with cidr bit count.
//   If it hits an active block (ancestor) on its path down the
// trie, the new insertion aborts.  Once the exact path length
// is reached, it marks the current node and completely
// deletes any existing children nodes branching beneath it.
// returns TRUE if netblock was actually added, false if not.

/*
    typedef struct TrieNode
    {
        struct TrieNode *children[2];
        DWORD count[2];
        bool is_block; // Marks if this specific prefix represents an active netblock
    } TrieNode;

    typedef struct
    {
        DWORD IP;
        DWORD bits;
    } IPTYPE;

*/


bool insert_netblock(TrieNode* root, IPTYPE ip, WORD DateStamp)
{
    TrieNode* current = root;
    DWORD i;
    int bit;

    // Ensure bit boundaries are safe
    if (ip.bits > 32) ip.bits = 32;

    for (i = 0; i < ip.bits; i++)
    {
        // If we encounter an existing shorter netblock prefix,
        // this new block is already covered. We ignore it.
        if (current->is_block)
        {
            current->DateAdded = DateStamp;   // update date
            return(false);
        }

        // Extract the i-th bit from left to right (MSB to LSB)
        bit = (ip.IP >> (31 - i)) & 1;

        if (!current->children[bit])
        {
            current->children[bit] = create_node();
        }
        current = current->children[bit];
    }

    // This block covers this precise prefix.
    // It replaces everything below it by pruning child paths.

    if (current->is_block)
    {
        current->DateAdded = DateStamp;   // update date
        return false; // Already existed, not a "new" addition
    }

    current->is_block = true;
    current->DateAdded = DateStamp;   // update date
    free_subtree(current->children[0]);
    free_subtree(current->children[1]);
    current->children[0] = NULL;
    current->children[1] = NULL;

    return(true);
}


// Count the nodes in the trie.
//   Count cidr blocks as containing all their capacity.

// Call this via: ComputeTrieCounts(root, 0);
DWORD ComputeTrieCounts(TrieNode *node, int level)
{
    int bits_remaining;
    DWORD left_total = 0;
    DWORD right_total = 0;

    if (node == NULL) return 0;

    bits_remaining = 32 - level;

    // If this node is explicitly a solid block, it represents the entire
    // capacity of its subnet size. No need to look at its children.
    if (node->is_block)
    {
        node->count[0] = 0;
        node->count[1] = 0;

        // Return 2^(32-level). Handles 32-bit shift bounds carefully.
        if (bits_remaining >= 32) return 0xFFFFFFFF;
        return ((DWORD)1 << bits_remaining);
    }

    // Recurse to find the true, surviving weight of both children
    if (node->children[0]) left_total  = ComputeTrieCounts(node->children[0], level + 1);
    if (node->children[1]) right_total = ComputeTrieCounts(node->children[1], level + 1);

    // Commit the true totals to the tracking arrays
    node->count[0] = left_total;
    node->count[1] = right_total;

    return left_total + right_total;
}


void CompressTrieSub(TrieNode *node, int level)
{
    int bits_remaining;
    QWORD total_possible, total_blocked;
    QWORD lhs_math, rhs_math; // to hold the percentage math

    if (node == NULL || node->is_block) return;

    bits_remaining = 32 - level;
    total_possible = ((QWORD)1 << bits_remaining);
    total_blocked = node->count[0] + node->count[1];

    // Check our aggressive threshold condition top-down
    // Only apply if we are at or deeper than our safety subnet mask (e.g. level 16)
    if (level >= G_MinCidr && total_possible > 0)
    {
        // Cast the 32-bit values to 64-bit BEFORE doing the multiplication
        lhs_math = total_blocked * 100;
        rhs_math = total_possible * G_Compress;

//printf("Level: %d, Possible: %u, Blocked: %u, Density: %u%%\n",
//  level, (DWORD)total_possible, (DWORD)total_blocked, (DWORD)(lhs_math / total_possible) );

        if (lhs_math >= rhs_math)
        {
            // The density matches! Convert this node into a block right now.
            node->is_block = true;

            // Free everything underneath instantly
            free_subtree(node->children[0]);
            free_subtree(node->children[1]);
            node->children[0] = NULL;
            node->children[1] = NULL;
            node->count[0] = 0;
            node->count[1] = 0;
            return; // Truncation complete, do not dig deeper
        }
    }

    // If this node didn't qualify for a full merge, keep checking its children
    CompressTrieSub(node->children[0], level + 1);
    CompressTrieSub(node->children[1], level + 1);
}


void CompressTrie(TrieNode *node)
{
    ComputeTrieCounts(node, 0);
    CompressTrieSub(node, 0);
}


// Helper to check if a node is completely empty (has no active block
// and no subtrees)
bool is_node_empty(TrieNode* node)
{
    if (!node) return true;
    return ((bool)(!node->is_block && !node->children[0] && !node->children[1]));
}

// Post-whitelist cleanup: recursively prunes redundant dead-ends
// from the bottom up
bool optimize_trie(TrieNode* node)
{
    if (!node) return true;

    // Recursively optimize children first
    if (node->children[0] && optimize_trie(node->children[0]))
    {
        free(node->children[0]);
        node->children[0] = NULL;
    }
    if (node->children[1] && optimize_trie(node->children[1]))
    {
        free(node->children[1]);
        node->children[1] = NULL;
    }

    // Return true if this node itself is now completely empty and
    // can be freed by its parent
    return is_node_empty(node);
}

// Whitelist Netblock Function
int whitelist_netblock(TrieNode* root, IPTYPE ip)
{
    TrieNode* current = root;
    DWORD i;
    int bit;

    if (ip.bits > 32) ip.bits = 32;

    for (i = 0; i < ip.bits; i++)
    {
        // If we encounter a broader active netblock along the path,
        // we must push its blocked status down to its children to
        // fragment it.
        if (current->is_block)
        {
            current->is_block = false;

            // Instantiate left child if missing and inherit the block
            // status.
            if (!current->children[0]) current->children[0] = create_node();
            current->children[0]->is_block = true;

            // Instantiate right child if missing and inherit the block
            // status
            if (!current->children[1]) current->children[1] = create_node();
            current->children[1]->is_block = true;
        }

        // Extract the i-th bit from left to right (MSB to LSB)
        bit = (ip.IP >> (31 - i)) & 1;

        // If the path doesn't exist, it means this range is already
        // not blacklisted. We can safely abort since there is nothing
        // to carve out.
        if (!current->children[bit])
        {
            return(0);   // Already not in blacklist
        }

        current = current->children[bit];
    }

    // We reached the exact target prefix depth.
    // If it was pushed down here or explicitly set, unblock it.
    current->is_block = false;

    // If this whitelist completely negated a subnet branch, it leaves
    // dead subtrees.  We clean up child subtrees if this newly
    // whitelisted node explicitly overrides them.
    free_subtree(current->children[0]);
    free_subtree(current->children[1]);
    current->children[0] = NULL;
    current->children[1] = NULL;

    // Optional: Run a quick pass from the root to clean up any newly
    // created empty nodes
    optimize_trie(root);

    return (1);   // found and removed
}
















// Export to ASCII File Function
// To output the items sequentially into an ASCII format file, we traverse the trie
// recursively using a Depth First Search (DFS). While traversing down, we
// reconstruct the IP address bit-by-bit.

// Helper to format a DWORD into standard dotted-decimal ASCII format
void write_ip_string(FILE* fp, IPTYPE ip, TrieNode* node)
{
    char *str = IP2Str(ip);

    if (node)
        fprintf(fp, "%04X:%s\n", (DWORD) node->DateAdded, str);
    else
        fprintf(fp, "%s\n", str);
}

// Recursive function to step down paths and record valid IP strings
// CurDate is the current datestamp.  Set to zero when writing whois file.
// This will cause the AddedDate to be added to the file.  If CurDate is
// non-zero, it is used to purge old IPs from the output list.

void export_trie_recursive(TrieNode* node, DWORD CurIp, DWORD depth, FILE* fp, WORD CurDate)
{
    IPTYPE ip;
    int days;

    if (!node) return;

    // If an active netblock is found, write it and stop traversing deeper
    if (node->is_block)
    {
        days = CurDate - node->DateAdded;
        if (days < 0) days = 0;
        if (CurDate == 0 || days < G_Expire)   // skip old entries
        {
            ip.IP = CurIp;
            ip.bits = depth;
            write_ip_string(fp, ip, (CurDate == 0) ? node : NULL);
        }
        return;
    }

    // Traverse the 0 branch
    if (node->children[0])
    {
        export_trie_recursive(node->children[0], CurIp, depth + 1, fp, CurDate);
    }

    // Traverse the 1 branch (setting the bit on at the correct depth position)
    if (node->children[1])
    {
        DWORD next_ip = CurIp | (1 << (31 - depth));
        export_trie_recursive(node->children[1], next_ip, depth + 1, fp, CurDate);
    }
}

// Master function to trigger file writing
void export_netblocks_to_file(TrieNode* root, const char* filename, WORD DateStamp)
{
    time_t raw_time;
    struct tm *time_info;
    char time_buffer[128];

    FILE* fp = fopen(filename, "w");

    if (!fp)
    {
        perror("Failed to open file for export");
        return;
    }

    fprintf(fp, "# This list was automatically created by %s.\n"
                "# Do not edit this list directly.\n", VERSION);

    time(&raw_time);  // Get the current system calendar time
    time_info = localtime(&raw_time);  // Convert to localtime structure

    // Format the time into a string
    strftime(time_buffer, sizeof(time_buffer),
        "# Asterisk Hacker List (Updated: %B %d, %Y %H:%M:%S)\n",
        time_info);

    // Write it to the ipset include file
    fputs(time_buffer, fp);

    // Root level starts at IP 0x00000000 and depth 0
    export_trie_recursive(root, 0, 0, fp, DateStamp);
    fclose(fp);
}


// The Lookup Function
// Checks if a single DWORD IP address is covered by any netblock in the trie.
// Returns true if covered, false otherwise.

bool is_ip_covered(TrieNode* root, DWORD ip, WORD DateStamp)
{
    TrieNode* current = root;
    DWORD i;
    int bit;

    if (!root) return false;


    // Traverse up to 32 levels deep (one level for each bit of the IPv4 address)
    for (i = 0; i < 32; i++)
    {
        // If we hit an active netblock node, this IP is covered by an existing block.
        if (current->is_block)
        {
            current->DateAdded = DateStamp;
            return true;
        }

        // Extract the i-th bit from left to right (MSB to LSB)
        bit = (ip >> (31 - i)) & 1;

        // Move to the next child branch
        current = current->children[bit];

        // If the path ends and we haven't hit a block node, the IP is not covered
        if (!current)
        {
            return false;
        }
    }

    // Exact match check for a specific /32 host entry at the final leaf node
    return current->is_block;
}





