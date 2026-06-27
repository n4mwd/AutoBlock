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

// This module handles storage of the IP addresses read from the asterisk log.

#include "AutoBlock.h"


// --- Data Structures ---

// Define the structure for a single entry in the hash table
typedef struct IpEntry
{
    DWORD ip_address; // The IPv4 address stored as a 32-bit integer
    DWORD count;            // The number of times this IP has been seen
    DWORD flags;            // Or'ed flags for each IP found
    struct IpEntry *next; // Pointer for separate chaining (handling collisions)
} IpEntry;


IpEntry *HashTab[HASH_SIZE];  // The hash table itself


// --- Hashing Function ---

/**
 * @param ip The 32-bit IP address.
 * @return size_t The calculated index into the hash table array.
 */
static size_t hash_ip(DWORD ip)
{
    // Simple modulo operation to map the 32-bit key to an index.
    // A common, simple technique is using the lower bits or XORing,
    // but modulo is standard for bucket placement.
    return ip % HASH_SIZE;
}

// --- Hash Table Management Functions ---

/**
 * @brief Initializes a new hash table.
 *
 * @param capacity The desired number of buckets.
 * @return HashTable* Pointer to the newly created hash table.
 */
void InitHashTable(void)
{
    int i;

    for (i = 0; i < HASH_SIZE; i++)  // initialize table
        HashTab[i] = NULL;

    return;
}

/**
 * @brief Frees the memory allocated for a single IP entry chain.
 *
 * @param entry The head of the linked list.
 */
static void free_chain(IpEntry *head)
{
    IpEntry *current = head;
    IpEntry *next;

    while (current != NULL)
    {
        next = current->next;
        free(current);
        current = next;
    }
}

/**
 * @brief Inserts or updates an IP address in the hash table.
 *
 * @param ht Pointer to the hash table.
 * @param ip The 32-bit IPv4 address to store.
 * @return int The new count of the IP (or -1 if insertion fails).
 */
int store_ip(DWORD ip, DWORD flags)
{
    size_t index;
    IpEntry *current;
    IpEntry *new_entry;

    //if (!ht) return -1;

    index = hash_ip(ip);
    current = HashTab[index];

    // Check if IP already exists (Search phase)
    while (current != NULL)
    {
        if (current->ip_address == ip)
        {
            // Found it: Increment the count and return
            current->count++;
            current->flags |= flags;   // combine flags
            return current->count;
        }
        current = current->next;
    }

    // IP does not exist: Create a new entry (Insertion phase)

    // Allocate memory for the new entry node
    new_entry = (IpEntry*)malloc(sizeof(IpEntry));
    if (!new_entry) return -1;

    // Initialize the new entry
    new_entry->ip_address = ip;
    new_entry->count = 1;
    new_entry->flags = flags;

    // Prepend to the linked list (simplest insertion)
    new_entry->next = HashTab[index];
    HashTab[index] = new_entry;

    return 1; // Successfully added a new IP
}


/**
 * @brief Retrieves the count for a specific IP address.
 *
 * @param ht Pointer to the hash table.
 * @param ip The 32-bit IPv4 address to look up.
 * @return int The count of the IP, or 0 if not found.
 */
int get_ip_count(DWORD ip)
{
    IpEntry *current;
    size_t index;

    index = hash_ip(ip);
    current = HashTab[index];

    while (current != NULL)
    {
        if (current->ip_address == ip)
        {
            return current->count;
        }
        current = current->next;
    }

    return 0; // Not found
}





/**
 * @brief Frees all memory associated with the hash table.
 *
 * @param ht Pointer to the hash table to destroy.
 */
void destroy_hash_table(void)
{
    size_t i;

    for (i = 0; i < HASH_SIZE; i++)
    {
        free_chain(HashTab[i]);
    }

}



// Flatten the hash table into a single linked list with the
// root node at HashTab[0].

int HashFlat(void)
{
    int i;
    IpEntry *root = NULL, *end = NULL, *current;
    int entry_count = 0; // Track the total number of flattened entries

    for (i = 0; i < HASH_SIZE; i++)
    {
        if (HashTab[i])
        {
            if (!root) root = HashTab[i];
            if (end) end->next = HashTab[i];

            // Walk the linked list with root at HashTab[i]
            // in order to find the last node.
            // Set end to point to last node.
            current = HashTab[i];
            while (current != NULL)
            {
                entry_count++;
                end = current;         // Keep track of the current node as the potential end
                current = current->next; // Move to the next node in the chain
            }

            // Clear the table slot as we move past it
            HashTab[i] = NULL;
        }
    }

    // Set the first element in the table to be the root of the flattened list
    HashTab[0] = root;

    // Return the total number of items in the list
    return entry_count;
}


// Read message log, parse the entries and add the IP into the hash table
// Return # of IPs added.  Return error code < 0  if errors.
// -1 file I/O error


int HashMessages(void)
{
    FILE *fp;
    char line[2048];
    int count = 0;
    DWORD ip, flags;

    InitHashTable();

    fp = fopen(G_AsteriskNoticeFile, "rt");
    if (!fp)
    {
        PrintErr(FATAL, "Could not open Asterisk Notice file: %s\n",
                     G_AsteriskNoticeFile);
        return(-1);
    }


    while (fgets(line, sizeof(line), fp) != NULL)
    {
        ip = ValidateHacker(line, &flags);
        if (ip)
        {
            store_ip(ip, flags);
            count++;
        }
    }

    fclose(fp);

    return(count);
}


// Walk the flattened linked list
// init = TRUE, initialize the list walker
// init = FALSE, return the next IP

DWORD GetNextHash(int init)
{
    static IpEntry *Current = NULL;
    DWORD ip;

    if (init)
    {
        Current = HashTab[0];   // initialize to root
        return(0);              // no value returned on init
    }

    if (!Current) return(0);    // No more to read

    ip = Current->ip_address;
    Current = Current->next;

    return(ip);
}











