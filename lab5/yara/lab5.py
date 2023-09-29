import os
import time
import yara
# 创建YARA规则对象并加载规则文件
rules = yara.compile('./lab5.y')

# 要扫描的目标文件夹路径
target_folder = './yara'

# 获取程序开始时间
start_time = time.time()

# 遍历目标文件夹
for root, dirs, files in os.walk(target_folder):
    for filename in files:
        file_path = os.path.join(root, filename)

        try:
            # 打开文件并读取内容
            with open(file_path, 'rb') as f:
                data = f.read()

            # 使用YARA规则进行匹配
            matches = rules.match(data=data)

            # 如果有匹配，处理匹配结果
            if matches:
                print(f"文件 {file_path} 匹配的规则: {matches}")

        except Exception as e:
            print(f"处理文件 {file_path} 时出错: {str(e)}")

# 获取程序结束时间
end_time = time.time()

# 计算并输出程序运行时间
elapsed_time = end_time - start_time
print(f"程序运行时间: {elapsed_time} 秒")
