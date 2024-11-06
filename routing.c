#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHILDREN 2

typedef struct TreeNode {
    struct TreeNode* children[MAX_CHILDREN];
    int is_end_of_ip;
    char route_info[50];  
} TreeNode;


TreeNode* createNode() {
    TreeNode* node = (TreeNode*)malloc(sizeof(TreeNode));
    node->is_end_of_ip = 0;
    node->route_info[0] = '\0';
    for (int i = 0; i < MAX_CHILDREN; i++) {
        node->children[i] = NULL;
    }
    return node;
}


void int_to_binary(int num, char* binary_str) {
    for (int i = 7; i >= 0; i--) {
        binary_str[7 - i] = (num & (1 << i)) ? '1' : '0';
    }
    binary_str[8] = '\0';  
}


void ip_to_binary(const char* ip, char* binary) {
    unsigned int octet;
    char octet_bin[9];
    binary[0] = '\0';  

    while (sscanf(ip, "%u", &octet) == 1) {
        int_to_binary(octet, octet_bin);
        strcat(binary, octet_bin);

        
        ip = strchr(ip, '.');
        if (ip == NULL) break;  
        ip++;  
    }
}


void binary_to_ip(const char* binary, char* ip) {
    for (int i = 0; i < 4; i++) {
        int octet = 0;
        for (int j = 0; j < 8; j++) {
            octet = (octet << 1) | (binary[i * 8 + j] - '0');
        }
        sprintf(ip + strlen(ip), i < 3 ? "%d." : "%d", octet);
    }
}


void insert(TreeNode* root, const char* ip_binary, const char* route_info) {
    TreeNode* current = root;
    for (int i = 0; ip_binary[i] != '\0'; i++) {
        int index = ip_binary[i] - '0';  
        if (current->children[index] == NULL) {
            current->children[index] = createNode();
        }
        current = current->children[index];
    }
    current->is_end_of_ip = 1;
    strcpy(current->route_info, route_info);
}


char* search(TreeNode* root, const char* ip_binary) {
    TreeNode* current = root;
    for (int i = 0; ip_binary[i] != '\0'; i++) {
        int index = ip_binary[i] - '0';
        if (current->children[index] == NULL) {
            return NULL;
        }
        current = current->children[index];
    }
    if (current->is_end_of_ip) {
        return current->route_info;
    }
    return NULL;
}


int find_available_ip(TreeNode* root, char* binary_ip, int depth, int mask_length) {
    if (depth == mask_length) {
        if (!root->is_end_of_ip) {
            root->is_end_of_ip = 1;
            return 1;
        }
        return 0;
    }
    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (root->children[i] == NULL) {
            root->children[i] = createNode();
        }
        binary_ip[depth] = '0' + i;
        if (find_available_ip(root->children[i], binary_ip, depth + 1, mask_length)) {
            return 1;
        }
    }
    return 0;
}


void allocate_new_ip_ipv4(TreeNode* root, const char* subnet_ipv4, int mask_length, const char* route_info) {
    char subnet_binary[33] = {0};
    char allocated_ip_binary[33] = {0};
    char allocated_ip[16] = {0};

    
    ip_to_binary(subnet_ipv4, subnet_binary);

    
    strncpy(allocated_ip_binary, subnet_binary, mask_length);

    
    if (find_available_ip(root, allocated_ip_binary, mask_length, 32)) {
        
        insert(root, allocated_ip_binary, route_info);

        
        binary_to_ip(allocated_ip_binary, allocated_ip);

        printf("Allocated new IP: %s with route info: %s\n", allocated_ip, route_info);
    } else {
        printf("No available IP in the specified subnet\n");
    }
}


void user_insert_ip(TreeNode* root) {
    char ip[16];
    char ip_binary[33];
    char route_info[50];
    
    printf("Enter the IP address (e.g., 192.168.1.1): ");
    scanf("%s", ip);
    printf("Enter the route information (e.g., Route_X): ");
    scanf("%s", route_info);
    
    
    ip_to_binary(ip, ip_binary);
    insert(root, ip_binary, route_info);
}


int main() {
    TreeNode* routing_table = createNode();
    
    char pre_inserted_ip[33];
    ip_to_binary("192.168.1.1",pre_inserted_ip);
    insert(routing_table,pre_inserted_ip,"Route_A");
    ip_to_binary("192.168.1.2",pre_inserted_ip);
    insert(routing_table,pre_inserted_ip,"Route_B");
    ip_to_binary("192.168.1.3",pre_inserted_ip);
    insert(routing_table,pre_inserted_ip,"Route_C");

    int choice;
    char subnet_ipv4[16];
    int mask_length;
    char route_info[50];
    char search_ip[16];
    char search_ip_binary[33];

    while(1) {
        printf("1: Insert an IP\n2: Allocate new IP in subnet\n3: routing a data packet\n");
        scanf("%d", &choice);

        switch(choice) {
            case 1:
                
                user_insert_ip(routing_table);
                break;
                
            case 2:
                
                printf("Enter the subnet (e.g., 192.168.1.0): ");
                scanf("%s", subnet_ipv4);
                printf("Enter the mask length (e.g., 24 for /24): ");
                scanf("%d", &mask_length);
                printf("Enter the route information: ");
                scanf("%s", route_info);
                allocate_new_ip_ipv4(routing_table, subnet_ipv4, mask_length, route_info);
                break;

            case 3:
                
                printf("Enter the destination IP address of the data packet (e.g., 192.168.1.1): ");
                scanf("%s", search_ip);
                ip_to_binary(search_ip, search_ip_binary);
                char* route = search(routing_table, search_ip_binary);
                
                if (route) {
                    printf("Found IP with route info: %s\nData packet directed to %s\n\n", route, route);
                } else {
                    printf("IP not found. Redirected to next hop\n\n");
                }
                break;

            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}
