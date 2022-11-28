template<typename T>
void list_erase(T *entry)
{
    entry->l->r = entry->r;
    entry->r->l = entry->l;
    entry->l = NULL;
    entry->r = NULL;
}

template<typename T>
void list_insert_before(T *r, T *entry)
{
    T *l = r->l;
    l->r = entry;
    r->l = entry;
    entry->l = l;
    entry->r = r;
}

template<typename T>
void list_move_to(T *r, T *entry)
{
    list_erase(entry);
    list_insert_before(r, entry);
}

template<typename T>
void list_move_to_back(T *leader, T *entry)
{
    list_move_to(leader, entry);
}

template<typename T>
void list_move_to_front(T *leader, T *entry)
{
    list_move_to(leader->r, entry);
}

template<typename T>
T *list_front(T *leader)
{
    return leader->r;
}

template<typename T>
bool list_empty(T *leader)
{
    return leader->l == leader;
}