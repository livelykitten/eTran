#pragma once

static inline bool exec_cmd(const std::string &cmd, std::string &result)
{
    printf("exec_cmd: %s\n", cmd.c_str());
    std::FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
        return false;

    char buffer[128];
    result.clear();
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        result += buffer;
    }

    pclose(pipe);
    return true;
}

static inline bool exec_cmd(const std::string &cmd)
{
    std::string unused_result;
    return exec_cmd(cmd, unused_result);
}